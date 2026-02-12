"""Encoding issue detection and auto-suggestion for moderation."""

import json
from collections import Counter
from pathlib import Path


# Common encoding patterns for BBS/MUD systems
_ENCODING_PATTERNS = {
    'cp437': ['\x80', '\x81', '\x82', '\x8b', '\x8c'],
    'cp850': ['\xa0', '\xa1', '\xa2'],
    'atascii': ['\x80', '\x81', '\x82'],
}


def suggest_encoding(banner_text, detected_encoding, scanner_detected):
    """Suggest the most likely correct encoding for a banner.

    :param banner_text: the banner text with encoding issues
    :param detected_encoding: the encoding we think it should be
    :param scanner_detected: what the scanner detected
    :returns: tuple of (suggested_encoding, confidence)
    """
    if detected_encoding and detected_encoding != 'unknown':
        return detected_encoding, 'current'

    if scanner_detected and scanner_detected != 'unknown':
        return scanner_detected, 'detected'

    # Heuristic: if text has many replacement chars, likely needs
    # a legacy encoding like cp437
    if banner_text:
        replacement_count = banner_text.count('\ufffd')
        if replacement_count > len(banner_text) * 0.05:
            return 'cp437', 'heuristic'

    return None, 'unknown'


class EncodingReviewTracker:
    """Track servers with encoding issues for moderation."""

    def __init__(self):
        """Initialize the tracker."""
        self.muds = []
        self.bbs = []

    def add_mud_issue(self, server_record):
        """Record a MUD server with encoding issues.

        :param server_record: dict with 'host', 'port', 'banner_before',
            'banner_after', 'encoding', 'display_encoding'
        """
        banner = (server_record.get('banner_before', '') or
                  server_record.get('banner_after', ''))
        if banner and '\ufffd' in banner:
            suggested, confidence = suggest_encoding(
                banner,
                server_record.get('display_encoding', ''),
                server_record.get('encoding', '')
            )
            self.muds.append({
                'host': server_record['host'],
                'port': server_record['port'],
                'detected_encoding': server_record.get('encoding'),
                'current_override': server_record.get(
                    'encoding_override', ''),
                'suggested_encoding': suggested,
                'suggestion_confidence': confidence,
                'issue_type': 'replacement_chars',
            })

    def add_bbs_issue(self, server_record):
        """Record a BBS server with encoding issues.

        :param server_record: dict with 'host', 'port', 'banner_before',
            'banner_after', 'encoding', 'display_encoding'
        """
        banner = (server_record.get('banner_before', '') or
                  server_record.get('banner_after', ''))
        if banner and '\ufffd' in banner:
            suggested, confidence = suggest_encoding(
                banner,
                server_record.get('encoding_override', ''),
                server_record.get('encoding', '')
            )
            self.bbs.append({
                'host': server_record['host'],
                'port': server_record['port'],
                'detected_encoding': server_record.get('encoding'),
                'current_override': server_record.get(
                    'encoding_override', ''),
                'suggested_encoding': suggested,
                'suggestion_confidence': confidence,
                'issue_type': 'replacement_chars',
            })

    def write_review_file(self, output_path):
        """Write encoding issues to a review file.

        :param output_path: path to write the JSON review file
        """
        review = {
            'mud_issues': self.muds,
            'bbs_issues': self.bbs,
            'total_issues': len(self.muds) + len(self.bbs),
        }

        with open(output_path, 'w') as f:
            json.dump(review, f, indent=2)

        if review['total_issues'] > 0:
            print(f"\n✓ Encoding review written to {output_path}",
                  f"({review['total_issues']} issues found)")


# Global tracker instance
_tracker = EncodingReviewTracker()


def get_tracker():
    """Get the global encoding review tracker."""
    return _tracker
