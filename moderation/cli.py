"""Argument parser and main entry point for the moderation tool."""

import argparse
import os
from pathlib import Path

from .banner_analysis import (
    discover_column_width_issues,
    discover_empty_banners,
    discover_renders_empty,
    discover_renders_small,
    review_column_width_issues,
    review_empty_banners,
    review_renders_empty,
    review_renders_small,
)
from .decisions import load_decisions, record_rejections, save_decisions
from .dedup import (
    find_cross_list_conflicts,
    find_dns_duplicates,
    find_duplicates,
    prune_dead,
)
from .encoding import (
    discover_encoding_issues,
    expunge_all_logs,
    review_encoding_issues,
    show_all_banners,
)
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
        help="skip DNS deduplication step",
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

    only_flags = (
        args.only_prune, args.only_dupes,
        args.only_cross, args.only_dns,
        args.only_encodings, args.only_columns,
        args.only_empty, args.only_renders_empty,
        args.only_renders_small,
    )
    any_only = any(only_flags)
    do_prune = args.only_prune or not any_only
    do_dupes = args.only_dupes or not any_only
    do_cross = args.only_cross or not any_only
    do_dns = (
        (args.only_dns or not any_only) and not args.skip_dns
    )
    do_encodings = args.only_encodings or not any_only
    do_columns = args.only_columns
    do_empty = args.only_empty
    do_renders_empty = args.only_renders_empty
    do_renders_small = args.only_renders_small

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

    if decisions is not None:
        save_decisions(args.decisions, decisions)
