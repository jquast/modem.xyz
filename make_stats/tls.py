"""TLS certificate checking with persistent caching."""

import asyncio
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE_FILE = os.path.join(_PROJECT_ROOT, 'tls_cache.json')
_TTL_DAYS = 7
_TTL_SECONDS = _TTL_DAYS * 86400


def _load_cache(path=_CACHE_FILE):
    """Load the TLS cache from disk.

    :param path: path to cache file
    :returns: dict mapping ``"host:port"`` to cache entries
    """
    if not os.path.isfile(path):
        return {}
    with open(path, 'r') as f:
        return json.load(f)


def _save_cache(cache, path=_CACHE_FILE):
    """Write the TLS cache to disk.

    :param cache: dict mapping ``"host:port"`` to cache entries
    :param path: path to cache file
    """
    with open(path + '.tmp', 'w') as f:
        json.dump(cache, f, indent=1, sort_keys=True)
    os.replace(path + '.tmp', path)


def _extract_cn(name):
    """Extract common name from an x509 Name object.

    :param name: :class:`cryptography.x509.Name`
    :returns: CN string, or empty string if not found
    """
    from cryptography.x509.oid import NameOID
    try:
        cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn_attrs[0].value if cn_attrs else ''
    except (IndexError, ValueError):
        return ''


def _check_cert(host, port, timeout=10):
    """Check TLS certificate for a single server.

    :param host: server hostname
    :param port: server port number
    :param timeout: connection timeout in seconds
    :returns: dict with ``status``, ``cn``, ``issuer_cn``, ``not_after``
    """
    # Stage 1: try full verification
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert()
            cn = ''
            for rdn in cert.get('subject', ()):
                for attr_type, attr_val in rdn:
                    if attr_type == 'commonName':
                        cn = attr_val
            issuer_cn = ''
            for rdn in cert.get('issuer', ()):
                for attr_type, attr_val in rdn:
                    if attr_type == 'commonName':
                        issuer_cn = attr_val
            not_after = cert.get('notAfter', '')
            return {
                'status': 'verified',
                'cn': cn,
                'issuer_cn': issuer_cn,
                'not_after': not_after,
            }
    except ssl.SSLCertVerificationError:
        pass
    except (OSError, socket.timeout):
        return {'status': 'unreachable', 'cn': '', 'issuer_cn': '',
                'not_after': ''}

    # Stage 2: connect without verification, parse DER cert
    from cryptography import x509
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            der = s.getpeercert(binary_form=True)
            if not der:
                return {'status': 'unreachable', 'cn': '',
                        'issuer_cn': '', 'not_after': ''}

            cert = x509.load_der_x509_certificate(der)
            cn = _extract_cn(cert.subject)
            issuer_cn = _extract_cn(cert.issuer)
            not_after = cert.not_valid_after_utc.strftime(
                '%Y-%m-%d')

            if cert.subject == cert.issuer:
                status = 'self_signed'
            elif cert.not_valid_after_utc < datetime.now(timezone.utc):
                status = 'expired'
            else:
                status = 'unverified'

            return {
                'status': status,
                'cn': cn,
                'issuer_cn': issuer_cn,
                'not_after': not_after,
            }
    except (OSError, socket.timeout, ValueError):
        return {'status': 'unreachable', 'cn': '', 'issuer_cn': '',
                'not_after': ''}


def _check_starttls(host, port, timeout=10):
    """Check whether a server offers telnet STARTTLS (option 46).

    Connects with telnetlib3, waits for option negotiation, then checks
    whether the server sent ``DO TLS``.

    :param host: server hostname
    :param port: server port number
    :param timeout: connection timeout in seconds
    :returns: ``'starttls'`` if the server offers TLS negotiation,
        ``'not_tls'`` if it does not, or ``'unreachable'`` on error
    """
    import telnetlib3
    from telnetlib3 import TLS

    async def _probe():
        try:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(
                    host, port,
                    connect_maxwait=timeout,
                    encoding=False),
                timeout=timeout)
            await asyncio.sleep(min(3, timeout))
            tls_offered = writer.local_option.get(TLS, None) is not None
            writer.close()
            return 'starttls' if tls_offered else 'not_tls'
        except (OSError, asyncio.TimeoutError):
            return 'unreachable'

    return asyncio.run(_probe())


def lookup_tls_certs(servers, cache_path=_CACHE_FILE, workers=8):
    """Check TLS certificates and annotate server records.

    Adds ``_tls_cert_status`` key to each server record that has a
    ``tls_port``.  Uses a persistent JSON cache with a 7-day TTL.

    :param servers: list of server record dicts
    :param cache_path: path to TLS cache file
    :param workers: number of parallel checking threads
    """
    cert_servers = []
    starttls_servers = []
    cache = _load_cache(cache_path)
    now = time.time()

    for s in servers:
        tls_port = s.get('tls_port', '')
        if not tls_port:
            continue
        if tls_port in ('1', str(s['port'])):
            starttls_servers.append((s['host'], s['port'], s))
        else:
            cert_servers.append((s['host'], int(tls_port), s))

    # --- Separate-port TLS: direct cert check ---
    cert_to_check = []
    for host, port, server in cert_servers:
        key = f"{host}:{port}"
        entry = cache.get(key)
        if entry and (now - entry.get('ts', 0)) < _TTL_SECONDS:
            server['_tls_cert_status'] = entry.get('status', '')
        else:
            cert_to_check.append((host, port, server, key))

    cert_cached = len(cert_servers) - len(cert_to_check)
    print(f"TLS certs: {cert_cached} cached,"
          f" {len(cert_to_check)} to check", file=sys.stderr)

    if cert_to_check:
        def _do_cert_check(item):
            host, port, server, key = item
            return key, server, _check_cert(host, port)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for done, (key, server, result) in enumerate(
                    pool.map(_do_cert_check, cert_to_check), 1):
                cache[key] = {**result, 'ts': now}
                server['_tls_cert_status'] = result['status']
                if done % 10 == 0 or done == len(cert_to_check):
                    print(f"  checked {done}/{len(cert_to_check)}",
                          file=sys.stderr, end="\r")
        print(file=sys.stderr)

    # --- Same-port TLS: STARTTLS probe ---
    starttls_to_check = []
    for host, port, server in starttls_servers:
        key = f"{host}:{port}:starttls"
        entry = cache.get(key)
        if entry and (now - entry.get('ts', 0)) < _TTL_SECONDS:
            server['_tls_cert_status'] = entry.get('status', '')
        else:
            starttls_to_check.append((host, port, server, key))

    starttls_cached = len(starttls_servers) - len(starttls_to_check)
    if starttls_servers:
        print(f"STARTTLS: {starttls_cached} cached,"
              f" {len(starttls_to_check)} to probe",
              file=sys.stderr)

    for done, (host, port, server, key) in enumerate(
            starttls_to_check, 1):
        status = _check_starttls(host, port)
        cache[key] = {'status': status, 'ts': now}
        server['_tls_cert_status'] = status
        if done % 10 == 0 or done == len(starttls_to_check):
            print(f"  probed {done}/{len(starttls_to_check)}",
                  file=sys.stderr, end="\r")
    if starttls_to_check:
        print(file=sys.stderr)

    if cert_to_check or starttls_to_check:
        _save_cache(cache, cache_path)

    for s in servers:
        s.setdefault('_tls_cert_status', '')
