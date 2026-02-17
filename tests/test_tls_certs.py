"""Tests for TLS certificate checking and caching."""

import json
import socket
import ssl
import time
from datetime import datetime, timezone, timedelta
from unittest import mock

import pytest

from make_stats.tls import (
    _check_cert,
    _check_starttls,
    _extract_cn,
    _load_cache,
    _save_cache,
    lookup_tls_certs,
)
from make_stats.muds import compute_statistics


class TestExtractCn:

    def test_extracts_cn(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ])
        assert _extract_cn(name) == 'example.com'

    def test_no_cn(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Acme'),
        ])
        assert _extract_cn(name) == ''


class TestCacheRoundtrip:

    def test_load_save(self, tmp_path):
        path = str(tmp_path / 'cache.json')
        data = {'host:1234': {'status': 'verified', 'ts': 1234.0}}
        _save_cache(data, path)
        loaded = _load_cache(path)
        assert loaded == data

    def test_load_missing(self, tmp_path):
        path = str(tmp_path / 'nonexistent.json')
        assert _load_cache(path) == {}


class TestCheckCert:

    def test_verified(self):
        cert_dict = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('commonName', 'CA'),),),
            'notAfter': 'May  1 19:03:41 2027 GMT',
        }
        mock_sock = mock.MagicMock()
        mock_sock.__enter__ = mock.MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = mock.MagicMock(return_value=False)
        mock_sock.getpeercert.return_value = cert_dict

        with mock.patch('make_stats.tls.ssl') as mock_ssl:
            ctx = mock.MagicMock()
            mock_ssl.create_default_context.return_value = ctx
            ctx.wrap_socket.return_value = mock_sock
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError

            result = _check_cert('example.com', 443)
            assert result['status'] == 'verified'
            assert result['cn'] == 'example.com'
            assert result['issuer_cn'] == 'CA'

    def test_self_signed(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'self.local'),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_sock_verified = mock.MagicMock()
        mock_sock_verified.__enter__ = mock.MagicMock(
            return_value=mock_sock_verified)
        mock_sock_verified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_verified.connect.side_effect = ssl.SSLCertVerificationError(
            1, 'self signed')

        mock_sock_unverified = mock.MagicMock()
        mock_sock_unverified.__enter__ = mock.MagicMock(
            return_value=mock_sock_unverified)
        mock_sock_unverified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_unverified.getpeercert.return_value = der_bytes

        call_count = [0]

        def make_ctx_side_effect():
            ctx = mock.MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:
                ctx.wrap_socket.return_value = mock_sock_verified
            else:
                ctx.wrap_socket.return_value = mock_sock_unverified
            return ctx

        with mock.patch('make_stats.tls.ssl') as mock_ssl:
            mock_ssl.create_default_context.return_value = (
                make_ctx_side_effect())
            mock_ssl.SSLContext.return_value = make_ctx_side_effect()
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError
            mock_ssl.PROTOCOL_TLS_CLIENT = ssl.PROTOCOL_TLS_CLIENT
            mock_ssl.CERT_NONE = ssl.CERT_NONE

            result = _check_cert('self.local', 443)
            assert result['status'] == 'self_signed'
            assert result['cn'] == 'self.local'

    def test_expired(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(65537, 2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'expired.local'),
        ])
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Some CA'),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_sock_verified = mock.MagicMock()
        mock_sock_verified.__enter__ = mock.MagicMock(
            return_value=mock_sock_verified)
        mock_sock_verified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_verified.connect.side_effect = ssl.SSLCertVerificationError(
            1, 'certificate has expired')

        mock_sock_unverified = mock.MagicMock()
        mock_sock_unverified.__enter__ = mock.MagicMock(
            return_value=mock_sock_unverified)
        mock_sock_unverified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_unverified.getpeercert.return_value = der_bytes

        call_count = [0]

        def make_ctx_side_effect():
            ctx = mock.MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:
                ctx.wrap_socket.return_value = mock_sock_verified
            else:
                ctx.wrap_socket.return_value = mock_sock_unverified
            return ctx

        with mock.patch('make_stats.tls.ssl') as mock_ssl:
            mock_ssl.create_default_context.return_value = (
                make_ctx_side_effect())
            mock_ssl.SSLContext.return_value = make_ctx_side_effect()
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError
            mock_ssl.PROTOCOL_TLS_CLIENT = ssl.PROTOCOL_TLS_CLIENT
            mock_ssl.CERT_NONE = ssl.CERT_NONE

            result = _check_cert('expired.local', 443)
            assert result['status'] == 'expired'
            assert result['cn'] == 'expired.local'
            assert result['issuer_cn'] == 'Some CA'

    def test_unverified(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(65537, 2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'unknown-ca.local'),
        ])
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Unknown CA'),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_sock_verified = mock.MagicMock()
        mock_sock_verified.__enter__ = mock.MagicMock(
            return_value=mock_sock_verified)
        mock_sock_verified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_verified.connect.side_effect = ssl.SSLCertVerificationError(
            1, 'unable to verify')

        mock_sock_unverified = mock.MagicMock()
        mock_sock_unverified.__enter__ = mock.MagicMock(
            return_value=mock_sock_unverified)
        mock_sock_unverified.__exit__ = mock.MagicMock(return_value=False)
        mock_sock_unverified.getpeercert.return_value = der_bytes

        call_count = [0]

        def make_ctx_side_effect():
            ctx = mock.MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:
                ctx.wrap_socket.return_value = mock_sock_verified
            else:
                ctx.wrap_socket.return_value = mock_sock_unverified
            return ctx

        with mock.patch('make_stats.tls.ssl') as mock_ssl:
            mock_ssl.create_default_context.return_value = (
                make_ctx_side_effect())
            mock_ssl.SSLContext.return_value = make_ctx_side_effect()
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError
            mock_ssl.PROTOCOL_TLS_CLIENT = ssl.PROTOCOL_TLS_CLIENT
            mock_ssl.CERT_NONE = ssl.CERT_NONE

            result = _check_cert('unknown-ca.local', 443)
            assert result['status'] == 'unverified'
            assert result['cn'] == 'unknown-ca.local'
            assert result['issuer_cn'] == 'Unknown CA'

    def test_unreachable(self):
        with mock.patch('make_stats.tls.ssl') as mock_ssl:
            ctx = mock.MagicMock()
            mock_ssl.create_default_context.return_value = ctx
            mock_sock = mock.MagicMock()
            mock_sock.__enter__ = mock.MagicMock(
                return_value=mock_sock)
            mock_sock.__exit__ = mock.MagicMock(return_value=False)
            mock_sock.connect.side_effect = OSError('refused')
            ctx.wrap_socket.return_value = mock_sock
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError

            result = _check_cert('dead.example.com', 443)
            assert result['status'] == 'unreachable'


class TestCheckStarttls:

    def test_starttls_offered(self):
        mock_writer = mock.MagicMock()
        mock_writer.local_option.get.return_value = False
        mock_reader = mock.MagicMock()

        async def fake_open(*a, **kw):
            return mock_reader, mock_writer

        with mock.patch('telnetlib3.open_connection', fake_open):
            result = _check_starttls('example.com', 4000)
        assert result == 'starttls'

    def test_starttls_not_offered(self):
        mock_writer = mock.MagicMock()
        mock_writer.local_option.get.return_value = None
        mock_reader = mock.MagicMock()

        async def fake_open(*a, **kw):
            return mock_reader, mock_writer

        with mock.patch('telnetlib3.open_connection', fake_open):
            result = _check_starttls('example.com', 4000)
        assert result == 'not_tls'

    def test_unreachable(self):
        async def fake_open(*a, **kw):
            raise OSError('refused')

        with mock.patch('telnetlib3.open_connection', fake_open):
            result = _check_starttls('example.com', 4000)
        assert result == 'unreachable'


class TestLookupTlsCerts:

    def test_annotates_records(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000,
             'tls_port': '4001'},
            {'host': 'b.com', 'port': 5000,
             'tls_port': ''},
        ]
        cache_data = {
            'a.com:4001': {
                'status': 'verified', 'cn': 'a.com',
                'issuer_cn': 'CA', 'not_after': '2027-01-01',
                'ts': time.time(),
            }
        }
        _save_cache(cache_data, cache_path)

        lookup_tls_certs(servers, cache_path=cache_path)
        assert servers[0]['_tls_cert_status'] == 'verified'
        assert servers[1]['_tls_cert_status'] == ''

    def test_same_port_probes_starttls(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000,
             'tls_port': '1'},
        ]
        with mock.patch('make_stats.tls._check_starttls') as m:
            m.return_value = 'not_tls'
            lookup_tls_certs(servers, cache_path=cache_path)
        assert servers[0]['_tls_cert_status'] == 'not_tls'
        m.assert_called_once_with('a.com', 4000)

    def test_same_port_explicit_probes_starttls(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000,
             'tls_port': '4000'},
        ]
        with mock.patch('make_stats.tls._check_starttls') as m:
            m.return_value = 'starttls'
            lookup_tls_certs(servers, cache_path=cache_path)
        assert servers[0]['_tls_cert_status'] == 'starttls'

    def test_starttls_cached(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000,
             'tls_port': '1'},
        ]
        cache_data = {
            'a.com:4000:starttls': {
                'status': 'not_tls', 'ts': time.time(),
            }
        }
        _save_cache(cache_data, cache_path)
        lookup_tls_certs(servers, cache_path=cache_path)
        assert servers[0]['_tls_cert_status'] == 'not_tls'

    def test_stale_cache_triggers_check(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000,
             'tls_port': '4001'},
        ]
        old_ts = time.time() - (8 * 86400)
        cache_data = {
            'a.com:4001': {
                'status': 'verified', 'cn': 'a.com',
                'issuer_cn': 'CA', 'not_after': '2027-01-01',
                'ts': old_ts,
            }
        }
        _save_cache(cache_data, cache_path)

        with mock.patch('make_stats.tls._check_cert') as mock_check:
            mock_check.return_value = {
                'status': 'expired', 'cn': 'a.com',
                'issuer_cn': 'CA', 'not_after': '2025-01-01',
            }
            lookup_tls_certs(servers, cache_path=cache_path)

        assert servers[0]['_tls_cert_status'] == 'expired'
        mock_check.assert_called_once_with('a.com', 4001)

    def test_no_tls_servers(self, tmp_path):
        cache_path = str(tmp_path / 'tls_cache.json')
        servers = [
            {'host': 'a.com', 'port': 4000, 'tls_port': ''},
        ]
        lookup_tls_certs(servers, cache_path=cache_path)
        assert servers[0]['_tls_cert_status'] == ''


def _make_server(host, port, tls_port='', tls_cert_status='',
                 codebase='', family='', has_mssp=True,
                 fingerprint='fp1'):
    """Build a minimal server record for compute_statistics."""
    return {
        'host': host, 'port': port, 'ip': '1.2.3.4',
        'connected': '2026-01-01', 'fingerprint': fingerprint,
        'has_mssp': has_mssp, 'players': 0, 'created': '',
        'protocols': {}, 'offered': [], 'requested': [],
        'refused': [], 'mssp': {
            'CODEBASE': codebase, 'FAMILY': family,
        },
        'tls_port': tls_port,
        '_tls_cert_status': tls_cert_status,
        '_country_name': 'Unknown',
    }


class TestTlsStatsComputation:

    def test_tls_counts(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status='verified'),
            _make_server('b.com', 5000, tls_port='1',
                         tls_cert_status='self_signed'),
            _make_server('c.com', 6000),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_counts'] == {
            'TLS Enabled': 2, 'No TLS': 1,
        }

    def test_tls_cert_counts(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status='verified'),
            _make_server('b.com', 5000, tls_port='1',
                         tls_cert_status='self_signed'),
            _make_server('c.com', 6000, tls_port='6001',
                         tls_cert_status='expired'),
            _make_server('d.com', 7000),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_cert_counts'] == {
            'Verified': 1, 'Self Signed': 1, 'Expired': 1,
        }

    def test_tls_cert_counts_empty_status_excluded(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status=''),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_cert_counts'] == {}

    def test_tls_by_codebase(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         codebase='DikuMUD 1.0'),
            _make_server('b.com', 5000,
                         codebase='DikuMUD 2.0'),
            _make_server('c.com', 6000, tls_port='1',
                         codebase='LPMud'),
            _make_server('d.com', 7000,
                         codebase='LPMud'),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_by_codebase']['DikuMUD'] == {
            'tls': 1, 'no_tls': 1,
        }
        assert stats['tls_by_codebase']['LPMud'] == {
            'tls': 1, 'no_tls': 1,
        }

    def test_tls_by_codebase_falls_back_to_family(self):
        servers = [
            _make_server('a.com', 4000, tls_port='1',
                         family='Evennia'),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_by_codebase']['Evennia'] == {
            'tls': 1, 'no_tls': 0,
        }

    def test_not_tls_excluded_from_counts(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status='verified'),
            _make_server('b.com', 5000, tls_port='1',
                         tls_cert_status='not_tls'),
            _make_server('c.com', 6000),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_counts'] == {
            'TLS Enabled': 1, 'No TLS': 2,
        }
        assert stats['tls_misreport_count'] == 1

    def test_not_tls_excluded_from_cert_counts(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status='verified'),
            _make_server('b.com', 5000, tls_port='1',
                         tls_cert_status='not_tls'),
            _make_server('c.com', 6000, tls_port='6001',
                         tls_cert_status='self_signed'),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_cert_counts'] == {
            'Verified': 1, 'Self Signed': 1,
        }
        assert 'Not Tls' not in stats['tls_cert_counts']
        assert stats['tls_misreport_count'] == 1

    def test_not_tls_excluded_from_codebase(self):
        servers = [
            _make_server('a.com', 4000, tls_port='4001',
                         tls_cert_status='verified',
                         codebase='DikuMUD'),
            _make_server('b.com', 5000, tls_port='1',
                         tls_cert_status='not_tls',
                         codebase='DikuMUD'),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_by_codebase']['DikuMUD'] == {
            'tls': 1, 'no_tls': 1,
        }

    def test_no_tls_servers(self):
        servers = [
            _make_server('a.com', 4000),
            _make_server('b.com', 5000),
        ]
        stats = compute_statistics(servers)
        assert stats['tls_counts'] == {
            'TLS Enabled': 0, 'No TLS': 2,
        }
        assert stats['tls_misreport_count'] == 0
        assert stats['tls_cert_counts'] == {}
        assert stats['tls_by_codebase'] == {}
