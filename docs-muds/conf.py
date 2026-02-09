"""Sphinx configuration for muds.modem.xyz."""

import datetime
import os

project = "muds.modem.xyz"
if datetime.datetime.now().year != 2026:
    copyright = f"2026-{datetime.datetime.now().year}, Jeff Quast"
else:
    copyright = f"2026 Jeff Quast"
author = "Jeff Quast"
release = "0.1.0"

extensions = [
    "sphinxcontrib.jquery",
    "sphinx_datatables",
]

datatables_options = {
    "paging": False,
    "info": False,
    "searching": True,
}

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static",
                     os.path.join(os.path.dirname(__file__), '..', '_static')]
html_baseurl = "https://muds.modem.xyz/"

html_theme_options = {
    "style_nav_header_background": "#1a1a2e",
    "navigation_depth": 3,
}

html_show_sphinx = False
html_show_copyright = False


def _make_class_role(class_name):
    """Create a simple RST role that wraps text with a CSS class."""
    from docutils import nodes

    def role(name, rawtext, text, lineno, inliner, options={}, content=[]):
        node = nodes.inline(rawtext, text, classes=[class_name])
        return [node], []
    return role


def _tls_lock_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """RST role that renders a TLS padlock icon with tooltip."""
    from docutils import nodes
    html = f'<span class="tls-lock" title="Supports TLS">{text}</span>'
    node = nodes.raw('', html, format='html')
    return [node], []


def _pay_icon_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """RST role that renders a pay-to-play dollar icon with tooltip."""
    from docutils import nodes
    html = f'<span class="pay-icon" title="Pay to Play">{text}</span>'
    node = nodes.raw('', html, format='html')
    return [node], []


def setup(app):
    from docutils.parsers.rst import roles
    roles.register_local_role('proto-yes', _make_class_role('proto-yes'))
    roles.register_local_role('proto-no', _make_class_role('proto-no'))
    roles.register_local_role('proto-negotiated',
                              _make_class_role('proto-negotiated'))
    roles.register_local_role('tls-lock', _tls_lock_role)
    roles.register_local_role('pay-icon', _pay_icon_role)

    app.add_css_file("dos-theme.css")
    app.add_js_file("custom_table_sort.js")
