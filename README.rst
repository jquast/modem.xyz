Website source for https://muds.modem.xyz/ and https://bbs.modem.xyz/

Overview
========

This project scans, fingerprints, and catalogs publicly accessible telnet
servers — BBS systems, MUDs, and other interesting places.  The pipeline
produces static Sphinx sites with terminal banner screenshots and service
metadata.

The server lists ``bbslist.txt`` and ``mudlist.txt`` use the format::

    host port [encoding [columns]]

For example::

    vert.synchro.net 23
    bbs.example.com 64 petscii 40
    foremxebbs.ddns.net 9000 atascii

Discovery
=========

There are several ways to find new servers to add to the lists.

Shodan searches
---------------

Search Shodan for known BBS and MUD software signatures.  This uses the
``shodan`` CLI (requires a paid API key)::

    # BBS software (Synchronet, Mystic, MajorBBS, Enigma, WWIV, etc.)
    python3 scan.py --shodan-bbs

    # MUD software (DikuMUD, CircleMUD, SMAUG, FluffOS, LPMud, etc.)
    python3 scan.py --shodan-muds

    # ANSI terminal services by escape sequence signatures
    python3 scan.py --shodan-general

Results are saved to ``nmap/data/shodan/`` as timestamped files in
``bbslist.txt``-compatible format with banner comments.

Nmap port scanning
------------------

Scan all 65535 TCP ports on every host in the list to discover additional
services (alternate telnet ports, rlogin, IRC, gopher, PETSCII, etc.)::

    # All-ports banner scan with resume support
    sudo python3 nmap/scan-banner.py

    # Service version detection on open ports with no banner
    sudo python3 nmap/scan-service.py

    # Or run both in sequence
    sudo ./run-all.sh

The banner scan identifies open ports and captures banners.  The service
scan follows up with nmap's ``-sV`` version probes on ports that didn't
produce a banner, plus ``-O`` OS fingerprinting.

Both scripts support ``--resume`` (default) to skip already-scanned hosts,
and store results in ``nmap/data/banner-scan/`` and
``nmap/data/service-scan/``.

Querying scan results
~~~~~~~~~~~~~~~~~~~~~

The query tool provides live analysis of nmap banner-scan data::

    python3 nmap/query.py                   # full dashboard
    python3 nmap/query.py --host HOST       # single host detail
    python3 nmap/query.py --service irc     # hosts with a service
    python3 nmap/query.py --software mystic # hosts running software
    python3 nmap/query.py --versions        # software and OS summary
    python3 nmap/query.py | less -R         # pipe with color

Escape sequence analysis
~~~~~~~~~~~~~~~~~~~~~~~~

Analyze terminal escape sequence frequency across collected banners::

    python3 nmap/seq-frequency.py
    python3 nmap/seq-frequency.py --by-banner --top 30

Moderation
==========

The moderation tool reviews and maintains the server lists::

    python3 -m moderation --only-shodan   # review Shodan discoveries
    python3 -m moderation --only-nmap     # review nmap discoveries
    python3 -m moderation --only-dns      # deduplicate by DNS
    python3 -m moderation --only-prune    # remove dead servers
    python3 -m moderation                 # run all checks

Server Fingerprinting
=====================

Once the server lists are ready, run the telnet fingerprint scanner to
collect session data and banners from each server::

    # Scan BBS servers
    python3 scan.py --list bbslist.txt --data-dir data-bbs

    # Scan MUD servers
    python3 scan.py --list mudlist.txt --data-dir data-muds

    # Rescan all (ignore existing logs)
    python3 scan.py --list bbslist.txt --data-dir data-bbs --refresh

The scanner uses ``telnetlib3-fingerprint`` to establish a telnet session,
negotiate terminal options, and capture the login banner.  Results are
saved as JSON in ``server/`` subdirectories.

Fingerprint moderation
----------------------

Review and fix issues in the collected fingerprint data::

    # Fix encoding issues (wrong codepage, mojibake)
    python3 -m moderation --only-encodings

    # Find servers responding with HTTP instead of telnet
    python3 -m moderation --only-http

    # Find empty banners or banners that render to blank screens
    python3 -m moderation --only-empty
    python3 -m moderation --only-renders-empty
    python3 -m moderation --only-renders-small

    # Suggest column width overrides for rendering
    python3 -m moderation --only-columns

    # Discover MSSP-advertised TLS ports
    python3 -m moderation --only-tls

    # Run all checks
    python3 -m moderation

Building the sites
==================

Generate the static Sphinx sites::

    python3 make_stats.py --bbs
    python3 make_stats.py --muds
