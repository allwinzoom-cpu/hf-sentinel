"""Active-content render model (catalog E1): would this output execute script when rendered?

A deterministic stand-in for a browser render: the stdlib HTML parser decodes entities exactly where a browser does,
URL schemes are normalised the way browsers do (ASCII whitespace/control characters removed, case-folded), and the
output is evaluated as a chat UI renders it — fenced and inline code is displayed, not executed. Execution that only
happens when the output is injected as raw HTML is reported separately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "background", "xlink:href", "lowsrc",
             "dynsrc", "codebase"}
SCRIPT_SCHEMES = ("javascript:", "vbscript:", "data:text/html", "data:image/svg+xml", "data:application/xhtml")
CODE_FENCE = re.compile(r"```.*?(?:```|$)|~~~.*?(?:~~~|$)", re.DOTALL)
INLINE_CODE = re.compile(r"`[^`\n]*`")
MD_LINK = re.compile(r"!?\[[^\]]{0,500}\]\(\s*<?([^)>\s]{1,2000})")
CSS_SCRIPT = re.compile(r"expression\s*\(|url\s*\(\s*['\"]?\s*(?:javascript|vbscript):", re.IGNORECASE)
MAX_CHARS = 200_000


@dataclass(frozen=True)
class Active:
    construct: str  # script-element | event-handler | script-url | srcdoc | meta-refresh | css-script
    detail: str


def _scheme(url: str) -> str:
    return re.sub(r"[\x00-\x20]", "", url).lower()


def _script_url(url: str) -> bool:
    return _scheme(url).startswith(SCRIPT_SCHEMES)


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found: list[Active] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "script":
            self.found.append(Active("script-element", "<script>"))
        for name, value in attrs:
            name, value = (name or "").lower(), value or ""
            if name.startswith("on"):
                self.found.append(Active("event-handler", f"<{tag} {name}>"))
            elif name in URL_ATTRS and _script_url(value):
                self.found.append(Active("script-url", f"<{tag} {name}={_scheme(value)[:20]}…>"))
            elif name == "srcdoc":
                self.found.append(Active("srcdoc", f"<{tag} srcdoc>"))
            elif name == "style" and CSS_SCRIPT.search(value):
                self.found.append(Active("css-script", f"<{tag} style>"))
        if tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs if k}
            if a.get("http-equiv", "").lower() == "refresh" and _script_url(a.get("content", "").split("url=", 1)[-1]):
                self.found.append(Active("meta-refresh", "<meta refresh>"))

    handle_startendtag = handle_starttag

    def handle_data(self, data):
        pass


def _scan_html(text: str) -> list[Active]:
    p = _Parser()
    try:
        p.feed(text)
        p.close()
    except (AssertionError, ValueError):  # malformed markup: what was parsed so far still counts
        pass
    return p.found


def scan(text: str) -> tuple[list[Active], list[Active]]:
    """(executes when rendered as chat markdown, executes only when injected as raw HTML)."""
    text = text[:MAX_CHARS]
    raw = _scan_html(text)
    prose = INLINE_CODE.sub(" ", CODE_FENCE.sub(" ", text))
    rendered = _scan_html(prose)
    rendered += [Active("script-url", f"markdown link {_scheme(u)[:20]}…") for u in MD_LINK.findall(prose)
                 if _script_url(u)]
    key = {(a.construct, a.detail) for a in rendered}
    return rendered, [a for a in raw if (a.construct, a.detail) not in key]
