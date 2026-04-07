"""Argument parser and main entry point for the moderation tool."""

import argparse
import os
from pathlib import Path

from .banner_analysis import (
    _BBS_IN_BANNER_RE,
    _MUD_IN_BANNER_RE,
    discover_column_width_issues,
    discover_empty_banners,
    discover_http_banners,
    discover_misplaced_servers,
    discover_nontelnet_banners,
    discover_renders_empty,
    discover_renders_small,
    review_column_width_issues,
    review_empty_banners,
    review_http_banners,
    review_misplaced_servers,
    review_nontelnet_banners,
    review_renders_empty,
    review_renders_small,
)
from .decisions import load_decisions, record_rejections, save_decisions
from .dedup import (
    find_cross_list_conflicts,
    find_dns_duplicates,
    find_duplicates,
    prune_dead,
    remove_rlogin_duplicates,
)
from .encoding import (
    discover_encoding_issues,
    expunge_all_logs,
    review_encoding_issues,
    show_all_banners,
)
from .rlogin import (
    discover_codepage_prompts,
    discover_rlogin_banners,
    review_codepage_prompts,
    review_rlogin_banners,
)
from .tls import discover_tls_ports, review_tls_ports
from .util import (
    DEFAULT_BBS_DATA,
    DEFAULT_BBS_LIST,
    DEFAULT_DECISIONS,
    DEFAULT_LOGS,
    DEFAULT_MUD_DATA,
    DEFAULT_MUD_LIST,
    _HERE,
)


def _get_argument_parser():
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Moderate MUD and BBS server lists: prune dead"
            " servers, find duplicates, and resolve"
            " cross-list conflicts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scope = parser.add_argument_group("scope (default: both)")
    scope_mx = scope.add_mutually_exclusive_group()
    scope_mx.add_argument(
        "--mud", action="store_true",
        help="only moderate the MUD list",
    )
    scope_mx.add_argument(
        "--bbs", action="store_true",
        help="only moderate the BBS list",
    )

    mode = parser.add_argument_group("mode (default: all)")
    mode_mx = mode.add_mutually_exclusive_group()
    mode_mx.add_argument(
        "--only-prune", action="store_true",
        help="only prune dead servers",
    )
    mode_mx.add_argument(
        "--only-dupes", action="store_true",
        help="only find within-list duplicates",
    )
    mode_mx.add_argument(
        "--only-cross", action="store_true",
        help="only find entries in both MUD and BBS lists",
    )
    mode_mx.add_argument(
        "--only-dns", action="store_true",
        help="only remove IP entries that duplicate a hostname",
    )
    mode_mx.add_argument(
        "--only-rlogin", action="store_true",
        help="only remove rlogin (port 513) entries that"
             " duplicate another port for the same host",
    )
    mode_mx.add_argument(
        "--only-rlogin-tags", action="store_true",
        help="scan fingerprint banners for RLogin rejection messages"
             " and add 'rlogin' keyword to matching list entries,"
             " then delete their log files for re-scan",
    )
    mode_mx.add_argument(
        "--only-codepage", action="store_true",
        help="find servers whose banners contain an unanswered codepage"
             " selection prompt (e.g. '[ENTER]=CP437') and delete their"
             " log files so they are re-scanned with the updated client",
    )
    mode_mx.add_argument(
        "--only-encodings", action="store_true",
        help="only discover and fix encoding issues in banners",
    )
    mode_mx.add_argument(
        "--only-columns", action="store_true",
        help="only discover and suggest column width overrides",
    )
    mode_mx.add_argument(
        "--only-empty", action="store_true",
        help=("only find servers with fingerprint data"
              " but empty banners"),
    )
    mode_mx.add_argument(
        "--only-renders-empty", action="store_true",
        help=("only find banners that render"
              " to an empty screen"),
    )
    mode_mx.add_argument(
        "--only-renders-small", action="store_true",
        help=("only find banners whose rendered PNGs"
              " are tiny (<1KB)"),
    )
    mode_mx.add_argument(
        "--only-http", action="store_true",
        help=("only find servers responding with HTTP"
              " instead of telnet"),
    )
    mode_mx.add_argument(
        "--only-nontelnet", action="store_true",
        help=("only find servers with MySQL, RTSP, or IRC protocol"
              " banners that should be removed from the lists"),
    )
    mode_mx.add_argument(
        "--only-tls", action="store_true",
        help=("only discover MSSP-advertised TLS ports"
              " not in the server list"),
    )
    mode_mx.add_argument(
        "--only-shodan", action="store_true",
        help="review pending Shodan discoveries and add"
             " to server lists",
    )
    mode_mx.add_argument(
        "--only-nmap", action="store_true",
        help="discover new telnet/rlogin services from nmap"
             " banner-scan data",
    )
    mode_mx.add_argument(
        "--only-misplaced", action="store_true",
        help="find BBS-list servers whose banners mention MUD"
             " (and vice-versa) and offer to move them",
    )

    parser.add_argument(
        "--report-only", action="store_true",
        help="print report without interactive prompts",
    )
    parser.add_argument(
        "--prune-data", action="store_true",
        help="offer to delete data files for removed entries",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="show what would change without writing files",
    )
    parser.add_argument(
        "--show-all", metavar="ENCODING",
        help=("display raw banners for all servers with the"
              " given encoding (or 'all' for every encoding)"),
    )
    parser.add_argument(
        "--expunge-all", metavar="ENCODING",
        help=("delete log files for all servers with the"
              " given encoding (or 'all' for every encoding),"
              " allowing re-scan"),
    )
    parser.add_argument(
        "--batch-cross", action="store_true",
        help=("auto-resolve cross-list conflicts:"
              " MSSP present -> keep in MUD list,"
              " no MSSP -> keep in BBS list"),
    )
    parser.add_argument(
        "--skip-dns", action="store_true",
        help="(ignored, kept for compatibility)",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="ignore cached decisions, re-prompt everything",
    )

    paths = parser.add_argument_group("paths")
    paths.add_argument(
        "--mud-list", default=str(DEFAULT_MUD_LIST),
        help=f"path to MUD server list"
             f" (default: {DEFAULT_MUD_LIST})",
    )
    paths.add_argument(
        "--bbs-list", default=str(DEFAULT_BBS_LIST),
        help=f"path to BBS server list"
             f" (default: {DEFAULT_BBS_LIST})",
    )
    paths.add_argument(
        "--mud-data", default=str(DEFAULT_MUD_DATA),
        help=f"MUD data directory, containing server/"
             f" subdirectory (default: {DEFAULT_MUD_DATA})",
    )
    paths.add_argument(
        "--bbs-data", default=str(DEFAULT_BBS_DATA),
        help=f"BBS data directory, containing server/"
             f" subdirectory (default: {DEFAULT_BBS_DATA})",
    )
    paths.add_argument(
        "--logs", default=str(DEFAULT_LOGS),
        help=f"shared logs directory"
             f" (default: {DEFAULT_LOGS})",
    )
    paths.add_argument(
        "--decisions", default=str(DEFAULT_DECISIONS),
        help=f"decisions cache file"
             f" (default: {DEFAULT_DECISIONS})",
    )

    return parser


def main():
    """CLI entry point."""
    args = _get_argument_parser().parse_args()

    do_mud = not args.bbs
    do_bbs = not args.mud

    if args.show_all:
        if do_mud and os.path.isfile(args.mud_list):
            show_all_banners(
                args.mud_list, args.mud_data, args.show_all)
        if do_bbs and os.path.isfile(args.bbs_list):
            show_all_banners(
                args.bbs_list, args.bbs_data, args.show_all)
        return

    if args.expunge_all:
        if do_mud and os.path.isfile(args.mud_list):
            expunge_all_logs(
                args.mud_list, args.logs, args.expunge_all,
                data_dir=args.mud_data)
        if do_bbs and os.path.isfile(args.bbs_list):
            expunge_all_logs(
                args.bbs_list, args.logs, args.expunge_all,
                data_dir=args.bbs_data)
        return

    if args.only_shodan:
        from .shodan_discover import list_pending, load_discovery_file
        from .util import _prompt
        pending = list_pending()
        if not pending:
            print("No pending Shodan discoveries.")
            return
        print(f"\n{len(pending)} pending discovery file(s):\n")
        for path, list_type, count, date in pending:
            print(f"  [{list_type.upper()}] {os.path.basename(path)}"
                  f" — {count} entries ({date})")
        print()

        for path, list_type, count, date in pending:
            entries = load_discovery_file(path)
            if not entries:
                continue
            target_list = (args.bbs_list if list_type == 'bbs'
                           else args.mud_list)
            print(f"\n{'='*60}")
            print(f"  {os.path.basename(path)} — {list_type.upper()}"
                  f" — {len(entries)} entries")
            print(f"  Target: {target_list}")
            print(f"{'='*60}")

            if args.report_only:
                for host, port, comment in entries:
                    c = f"  # {comment}" if comment else ''
                    print(f"  {host} {port}{c}")
                continue

            accepted = []
            for host, port, comment in entries:
                c = comment.replace('\x00', '') if comment else ''
                c = f"\n    {c}" if c else ''
                ans = _prompt(
                    f"\n  {host} {port}{c}"
                    f"\n  Add? [y/n/a(ll)/s(kip file)] ",
                    "ynas")
                if ans == 's':
                    print("  Skipping rest of file.")
                    break
                if ans == 'a':
                    accepted.append((host, port))
                    accepted.extend(
                        (h, p) for h, p, _ in entries[
                            entries.index((host, port, comment)) + 1:])
                    print(f"  Accepting all remaining"
                          f" ({len(accepted)} total).")
                    break
                if ans == 'y':
                    accepted.append((host, port))

            if accepted and not args.dry_run:
                with open(target_list, 'a') as f:
                    for host, port in accepted:
                        f.write(f"{host} {port}\n")
                print(f"  Appended {len(accepted)} entries"
                      f" to {target_list}")
                # Archive processed file.
                archive = path + '.done'
                os.rename(path, archive)
                print(f"  Archived → {os.path.basename(archive)}")
            elif accepted:
                print(f"  Dry run: would append {len(accepted)}"
                      f" entries to {target_list}")
        return

    if args.only_nmap:
        from .nmap_discover import discover_from_nmap
        from .util import _prompt

        discoveries = discover_from_nmap(args.bbs_list, args.mud_list)
        if not discoveries:
            print("No new telnet services found in nmap data.")
            return

        muds = [d for d in discoveries if d['category'] == 'mud']
        bbs = [d for d in discoveries
               if d['category'] in ('bbs', 'other')]
        new_hosts = [d for d in discoveries if d.get('is_new_host')]
        new_ports = [d for d in discoveries if not d.get('is_new_host')]

        print(f"\nFound {len(discoveries)} new telnet services:"
              f" {len(muds)} MUD, {len(bbs)} BBS/other"
              f" ({len(new_hosts)} new hosts,"
              f" {len(new_ports)} new ports on known hosts)\n")

        if args.report_only:
            if muds:
                print(f"  === MUD ({len(muds)}) → {args.mud_list} ===")
                for d in muds:
                    print(f"  {d['host']} {d['port']}"
                          f"  # {d['banner'][:70]}")
            if bbs:
                print(f"\n  === BBS/other ({len(bbs)})"
                      f" → {args.bbs_list} ===")
                for d in bbs:
                    print(f"  {d['host']} {d['port']}"
                          f"  # {d['banner'][:70]}")
            return

        def _entry_line(d):
            enc = d.get('encoding', '')
            if enc:
                return f"{d['host']} {d['port']} {enc}"
            return f"{d['host']} {d['port']}"

        def _review(label, items, target):
            accepted = []
            print(f"  === {label} ({len(items)})"
                  f" → {target} ===")
            for d in items:
                banner = d['banner'][:60].replace('\n', ' ')
                new_tag = ' [NEW]' if d.get('is_new_host') else ''
                enc_tag = (f' [{d["encoding"]}]'
                           if d.get('encoding') else '')
                ans = _prompt(
                    f"\n  {d['host']} {d['port']}"
                    f"{enc_tag}{new_tag}"
                    f"\n    {banner}"
                    f"\n  Add? [y/n/a(ll)/s(kip)] ", "ynas")
                if ans == 's':
                    break
                if ans == 'a':
                    accepted.append(d)
                    idx = items.index(d)
                    accepted.extend(items[idx + 1:])
                    print(f"  Accepting all remaining"
                          f" ({len(accepted)} total).")
                    break
                if ans == 'y':
                    accepted.append(d)
            return accepted

        mud_accepted = []
        bbs_accepted = []

        if muds:
            mud_accepted = _review(
                'MUD candidates', muds, args.mud_list)

        if bbs:
            bbs_accepted = _review(
                'BBS/other candidates', bbs, args.bbs_list)

        if not args.dry_run:
            if mud_accepted:
                with open(args.mud_list, 'a') as f:
                    for d in mud_accepted:
                        f.write(_entry_line(d) + '\n')
                print(f"  Appended {len(mud_accepted)} to"
                      f" {args.mud_list}")
            if bbs_accepted:
                with open(args.bbs_list, 'a') as f:
                    for d in bbs_accepted:
                        f.write(_entry_line(d) + '\n')
                print(f"  Appended {len(bbs_accepted)} to"
                      f" {args.bbs_list}")
        else:
            if mud_accepted:
                print(f"  Dry run: would append"
                      f" {len(mud_accepted)} to {args.mud_list}")
            if bbs_accepted:
                print(f"  Dry run: would append"
                      f" {len(bbs_accepted)} to {args.bbs_list}")
        return

    only_flags = (
        args.only_prune, args.only_dupes,
        args.only_cross, args.only_dns,
        args.only_rlogin, args.only_rlogin_tags, args.only_codepage,
        args.only_encodings, args.only_columns,
        args.only_empty, args.only_renders_empty,
        args.only_renders_small, args.only_http,
        args.only_nontelnet, args.only_tls,
        args.only_misplaced,
    )
    any_only = any(only_flags)
    do_prune = args.only_prune or not any_only
    do_dupes = args.only_dupes
    do_cross = args.only_cross
    do_dns = args.only_dns
    do_rlogin = args.only_rlogin or not any_only
    do_rlogin_tags = args.only_rlogin_tags
    do_codepage = args.only_codepage
    do_encodings = args.only_encodings or not any_only
    do_columns = args.only_columns
    do_empty = args.only_empty or not any_only
    do_renders_empty = args.only_renders_empty
    do_renders_small = args.only_renders_small
    do_http = args.only_http or not any_only
    do_nontelnet = args.only_nontelnet
    do_tls = args.only_tls
    do_misplaced = args.only_misplaced

    if do_cross and (args.mud or args.bbs):
        do_cross = False
    if do_dns and (args.mud or args.bbs):
        do_dns = False

    decisions = None
    if not args.no_cache and not args.report_only:
        decisions = load_decisions(args.decisions)

    if do_dns:
        if (os.path.isfile(args.mud_list)
                and os.path.isfile(args.bbs_list)):
            mud_rm, bbs_rm = find_dns_duplicates(
                args.mud_list, args.bbs_list,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", mud_rm, "dns")
                record_rejections(
                    decisions, "bbs", bbs_rm, "dns")

    if do_rlogin:
        if do_mud and os.path.isfile(args.mud_list):
            removed = remove_rlogin_duplicates(
                args.mud_list,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", removed, "rlogin")
        if do_bbs and os.path.isfile(args.bbs_list):
            removed = remove_rlogin_duplicates(
                args.bbs_list,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "bbs", removed, "rlogin")

    if do_rlogin_tags:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_rlogin_banners(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_rlogin_banners(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_rlogin_banners(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No untagged RLogin rejection banners found.")

    if do_codepage:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_codepage_prompts(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_codepage_prompts(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_codepage_prompts(
                mud_issues, bbs_issues, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No unanswered codepage selection prompts found.")

    if do_prune:
        if do_mud and os.path.isfile(args.mud_list):
            removed = prune_dead(
                args.mud_list, args.mud_data, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", removed, "dead")
        if do_bbs and os.path.isfile(args.bbs_list):
            removed = prune_dead(
                args.bbs_list, args.bbs_data, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "bbs", removed, "dead")

    if do_dupes:
        if do_mud and os.path.isfile(args.mud_list):
            removed = find_duplicates(
                args.mud_list, args.mud_data,
                report_only=args.report_only,
                prune_data=args.prune_data,
                dry_run=args.dry_run,
                decisions=decisions,
                logs_dir=args.logs)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", removed, "duplicate")
        if do_bbs and os.path.isfile(args.bbs_list):
            removed = find_duplicates(
                args.bbs_list, args.bbs_data,
                report_only=args.report_only,
                prune_data=args.prune_data,
                dry_run=args.dry_run,
                decisions=decisions,
                logs_dir=args.logs)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "bbs", removed, "duplicate")

    if do_cross:
        if (os.path.isfile(args.mud_list)
                and os.path.isfile(args.bbs_list)):
            mud_rm, bbs_rm = find_cross_list_conflicts(
                args.mud_list, args.bbs_list,
                args.mud_data, args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run,
                decisions=decisions,
                batch_cross=args.batch_cross)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", mud_rm, "cross")
                record_rejections(
                    decisions, "bbs", bbs_rm, "cross")

    if do_encodings:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_encoding_issues(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_encoding_issues(
                args.bbs_data, args.bbs_list,
                default_encoding='cp437')

        if mud_issues or bbs_issues:
            review_encoding_issues(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No encoding issues detected.")

    if do_columns:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_column_width_issues(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_column_width_issues(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_column_width_issues(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No column width issues detected.")

    if do_empty:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_empty_banners(
                args.mud_data, args.mud_list, args.logs)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_empty_banners(
                args.bbs_data, args.bbs_list, args.logs)

        if mud_issues or bbs_issues:
            review_empty_banners(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No empty banner issues detected.")

    if do_renders_empty:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_renders_empty(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_renders_empty(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_renders_empty(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No banners that render to empty screen.")

    if do_renders_small:
        mud_banners = (
            _HERE / "docs-muds" / "_static" / "banners"
        )
        bbs_banners = (
            _HERE / "docs-bbs" / "_static" / "banners"
        )
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_renders_small(
                args.mud_data, args.mud_list,
                str(mud_banners),
                default_encoding=None)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_renders_small(
                args.bbs_data, args.bbs_list,
                str(bbs_banners),
                default_encoding='cp437')

        if mud_issues or bbs_issues:
            review_renders_small(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No banners with small renders detected.")

    if do_http:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_http_banners(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_http_banners(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            mud_rm, bbs_rm = review_http_banners(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", mud_rm, "http_banner")
                record_rejections(
                    decisions, "bbs", bbs_rm, "http_banner")
        else:
            print("No HTTP response banners detected.")

    if do_nontelnet:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_nontelnet_banners(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_nontelnet_banners(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            mud_rm, bbs_rm = review_nontelnet_banners(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data,
                bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
            if decisions and not args.dry_run:
                record_rejections(
                    decisions, "mud", mud_rm, "nontelnet_banner")
                record_rejections(
                    decisions, "bbs", bbs_rm, "nontelnet_banner")
        else:
            print("No non-Telnet protocol banners detected.")

    if do_tls:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_tls_ports(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_tls_ports(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_tls_ports(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list,
                report_only=args.report_only,
                dry_run=args.dry_run)

            if decisions is not None and not args.report_only:
                from .data import _parse_host_port_ssl_set
                from .decisions import find_stale_tls_decisions
                ssl_entries = set()
                if os.path.isfile(args.mud_list):
                    ssl_entries |= _parse_host_port_ssl_set(
                        args.mud_list)
                if os.path.isfile(args.bbs_list):
                    ssl_entries |= _parse_host_port_ssl_set(
                        args.bbs_list)
                stale = find_stale_tls_decisions(
                    decisions, ssl_entries)
                if stale:
                    print(f"\n  {len(stale)} cached dupe"
                          f" decision(s) may be stale"
                          f" (include TLS entries)")
                    from .util import _prompt
                    ans = _prompt(
                        "  Clear these decisions? [y/N] ",
                        "yn")
                    if ans == 'y':
                        for key in stale:
                            del decisions["dupes"][key]
                        print(f"  Cleared {len(stale)}"
                              f" stale decision(s)")
        else:
            print("No MSSP-advertised TLS ports to add.")

    if do_misplaced:
        bbs_issues = []
        mud_issues = []
        if os.path.isfile(args.bbs_list):
            bbs_issues = discover_misplaced_servers(
                args.bbs_data, args.bbs_list, _MUD_IN_BANNER_RE)
        if os.path.isfile(args.mud_list):
            mud_issues = discover_misplaced_servers(
                args.mud_data, args.mud_list, _BBS_IN_BANNER_RE)

        if bbs_issues or mud_issues:
            review_misplaced_servers(
                bbs_issues, mud_issues,
                args.bbs_list, args.mud_list,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No misplaced servers detected.")

    if decisions is not None:
        save_decisions(args.decisions, decisions)
