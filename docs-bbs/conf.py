"""Sphinx configuration for bbs.modem.xyz."""

import datetime
import os

project = "bbs.modem.xyz"
if datetime.datetime.now().year != 2026:
    copyright = f"2026-{datetime.datetime.now().year}, Jeff Quast"
else:
    copyright = f"2026 Jeff Quast"
author = "Jeff Quast"
now = datetime.datetime.now()
release = f"{now.year}.{now.month:02}.{now.day:02}"

extensions = [
    "sphinxcontrib.jquery",
    "sphinx_datatables",
    "sphinxcontrib.youtube",
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
html_baseurl = "https://bbs.modem.xyz/"

html_theme_options = {
    "style_nav_header_background": "#1a1a2e",
    "navigation_depth": 2,
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


def _copy_btn_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """RST role that renders a clipboard copy button for ``host port``."""
    import html as html_mod
    from docutils import nodes
    parts = text.rsplit(' ', 1)
    host = html_mod.escape(parts[0])
    port = html_mod.escape(parts[1]) if len(parts) > 1 else '23'
    markup = (
        f'<button class="copy-btn"'
        f' data-host="{host}" data-port="{port}"'
        f' title="Copy host and port"'
        f' aria-label="Copy {host} port {port} to clipboard">'
        f'<span class="copy-icon" aria-hidden="true">&#x1F4CB;</span>'
        f'</button>')
    node = nodes.raw('', markup, format='html')
    return [node], []


def setup(app):
    from docutils.parsers.rst import roles
    roles.register_local_role('proto-yes', _make_class_role('proto-yes'))
    roles.register_local_role('proto-no', _make_class_role('proto-no'))
    roles.register_local_role('proto-negotiated',
                              _make_class_role('proto-negotiated'))
    roles.register_local_role('tls-lock', _tls_lock_role)
    roles.register_local_role('copy-btn', _copy_btn_role)

    app.add_css_file("dos-theme.css")
    app.add_js_file("custom_table_sort.js")
