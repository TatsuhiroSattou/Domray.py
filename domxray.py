#!/usr/bin/env python3
"""
DOMXRay — analizador estático de taint-flow para DOM-XSS.

Hermano de JSHunter, mismo lexer y mismo crawler como base, pero un motor de
detección completamente distinto: en vez de buscar "strings sospechosos"
(secretos, endpoints), rastrea FLUJOS DE DATOS peligrosos —

    fuente no confiable (location.hash, document.cookie, postMessage, ...)
        --> llega sin sanitizar -->
    sink peligroso (innerHTML, eval, document.write, ...)

USO:
    python3 domxray.py -d ejemplo.com
    python3 domxray.py -l dominios.txt -o reporte.json --html reporte.html
    python3 domxray.py -f archivo_local.js
    python3 domxray.py -d ejemplo.com --depth 2 --max-pages 15

IMPORTANTE: usa esto solo contra objetivos para los que tengas autorización
explícita (programas de bug bounty, pentests contratados, tus propios
proyectos). Recon activo contra terceros sin permiso puede ser ilegal.
"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# ============================================================================
# LEXER — igual planteamiento que JSHunter: reconoce strings, templates,
# comentarios y regex literals reales. Pero acá no extraemos tokens para
# clasificar strings; lo usamos para producir una versión "limpia" del
# código (comentarios en blanco, todo lo demás intacto y en la misma
# posición) sobre la que corren los regex de sinks/fuentes — así un
# "innerHTML =" comentado o un ejemplo en un string de documentación no
# generan falsos positivos.
# ============================================================================


def strip_comments_preserve_offsets(src):
    """Devuelve una copia de src con // y /* */ reemplazados por espacios
    (menos los saltos de línea, que se preservan) para no desalinear los
    números de línea. Respeta strings, templates y regex literals: nunca
    entra en modo comentario si está dentro de uno de ellos."""
    n = len(src)
    out = list(src)
    i = 0
    last_significant = None  # último token no-trivial, para decidir si "/" puede ser regex

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]

        if c in " \t\r":
            i += 1
            continue
        if c == "\n":
            i += 1
            continue

        if c == "/" and i + 1 < n and src[i + 1] == "/":
            start = i
            while i < n and src[i] != "\n":
                i += 1
            blank(start, i)
            continue

        if c == "/" and i + 1 < n and src[i + 1] == "*":
            start = i
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                i += 1
            i = min(i + 2, n)
            blank(start, i)
            continue

        if c in "\"'":
            quote = c
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "\n":
                    break
                i += 1
            i = min(i + 1, n)
            last_significant = "string"
            continue

        if c == "`":
            i += 1
            depth = 0
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "$" and i + 1 < n and src[i + 1] == "{":
                    depth += 1
                    i += 2
                    continue
                if depth > 0 and src[i] == "}":
                    depth -= 1
                    i += 1
                    continue
                if src[i] == "`" and depth == 0:
                    i += 1
                    break
                i += 1
            last_significant = "string"
            continue

        if c == "/":
            prev_allows_regex = last_significant in (None, "punct", "keyword")
            if prev_allows_regex:
                start = i
                j = i + 1
                in_class = False
                ok = True
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    elif src[j] == "/" and not in_class:
                        j += 1
                        break
                    elif src[j] == "\n":
                        ok = False
                        break
                    j += 1
                if ok:
                    while j < n and src[j].isalpha():
                        j += 1
                    i = j
                    last_significant = "regex"
                    continue

        if re.match(r"[A-Za-z_$]", c):
            j = i
            while j < n and re.match(r"[A-Za-z0-9_$]", src[j]):
                j += 1
            word = src[i:j]
            last_significant = "keyword" if word in (
                "return", "typeof", "instanceof", "in", "of", "new", "delete",
                "void", "throw", "case", "do", "else", "yield", "await",
            ) else "ident"
            i = j
            continue

        if c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            i = j
            last_significant = "number"
            continue

        last_significant = "punct" if c not in ")]" else "ident"
        i += 1

    return "".join(out)


def mask_string_contents(clean):
    """Recibe el texto ya libre de comentarios y devuelve una copia donde el
    CONTENIDO LITERAL de strings/templates ('...', "...", `...`) queda en
    blanco -- para que un sink escrito como texto dentro de un string de
    ejemplo/documentación (ej: una variable que dice "no hagas
    el.innerHTML = location.hash") no dispare una detección. Lo que sí se
    conserva activo es el código real dentro de interpolaciones `${...}` de
    template literals, porque eso sí se ejecuta. Preserva longitud y
    posiciones exactas respecto a `clean`."""
    n = len(clean)
    out = list(clean)
    i = 0

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = clean[i]
        if c in "\"'":
            quote = c
            start = i + 1
            i += 1
            while i < n and clean[i] != quote:
                if clean[i] == "\\":
                    i += 2
                    continue
                if clean[i] == "\n":
                    break
                i += 1
            blank(start, i)
            i = min(i + 1, n)
            continue
        if c == "`":
            i += 1
            seg_start = i
            while i < n:
                if clean[i] == "\\":
                    i += 2
                    continue
                if clean[i] == "$" and i + 1 < n and clean[i + 1] == "{":
                    blank(seg_start, i)
                    i += 2
                    depth = 1
                    while i < n and depth > 0:
                        if clean[i] == "{":
                            depth += 1
                        elif clean[i] == "}":
                            depth -= 1
                        i += 1
                    seg_start = i
                    continue
                if clean[i] == "`":
                    blank(seg_start, i)
                    i += 1
                    break
                i += 1
            continue
        i += 1

    return "".join(out)


# ============================================================================
# EXTRACCIÓN DE EXPRESIONES — bracket-matching consciente de strings, para
# recortar exactamente "el argumento de esta llamada" o "el lado derecho de
# esta asignación" sin romperse con comas/paréntesis anidados.
# ============================================================================


def _skip_string(clean, i, n):
    """Si clean[i] abre un string/template, devuelve el índice justo
    después de cerrarlo. Si no, devuelve None."""
    if clean[i] not in "\"'`":
        return None
    quote = clean[i]
    j = i + 1
    while j < n:
        if clean[j] == "\\":
            j += 2
            continue
        if clean[j] == quote:
            return j + 1
        j += 1
    return n


def extract_call_args(clean, open_paren_idx, max_len=1500):
    """Dado el índice de un '(' de apertura, devuelve (texto_de_args, idx_tras_cierre)."""
    n = len(clean)
    depth = 1
    i = open_paren_idx + 1
    start = i
    limit = min(n, open_paren_idx + max_len)
    while i < limit:
        c = clean[i]
        skipped = _skip_string(clean, i, n)
        if skipped is not None:
            i = skipped
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return clean[start:i], i + 1
        i += 1
    return clean[start:i], i


def extract_rhs(clean, eq_idx, max_len=400):
    """Dado el índice justo después de un '=' de asignación, devuelve el
    lado derecho hasta ';' o '\\n' de nivel superior (fuera de brackets)."""
    n = len(clean)
    depth = 0
    i = eq_idx
    start = i
    limit = min(n, eq_idx + max_len)
    while i < limit:
        c = clean[i]
        skipped = _skip_string(clean, i, n)
        if skipped is not None:
            i = skipped
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and c == ";":
            break
        elif depth == 0 and c == "\n" and i > start:
            break
        i += 1
    return clean[start:i].strip(), i


# ============================================================================
# FUENTES / SINKS / SANITIZADORES
# ============================================================================

SOURCE_PATTERNS = [
    ("location.hash", re.compile(r"\blocation\s*\.\s*hash\b")),
    ("location.search", re.compile(r"\blocation\s*\.\s*search\b")),
    ("location.href", re.compile(r"\blocation\s*\.\s*href\b")),
    ("location.pathname", re.compile(r"\blocation\s*\.\s*pathname\b")),
    ("document.location", re.compile(r"\bdocument\s*\.\s*location\b")),
    ("document.referrer", re.compile(r"\bdocument\s*\.\s*referrer\b")),
    ("document.URL", re.compile(r"\bdocument\s*\.\s*URL\b")),
    ("document.cookie", re.compile(r"\bdocument\s*\.\s*cookie\b")),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b")),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\b")),
    (".searchParams.get(", re.compile(r"\.\s*searchParams\s*\.\s*get\s*\(")),
    ("postMessage data (event.data)", re.compile(r"\b(?:evt?|event|msg|message|e)\s*\.\s*data\b")),
    ("localStorage.getItem", re.compile(r"\blocalStorage\s*\.\s*getItem\s*\(")),
    ("sessionStorage.getItem", re.compile(r"\bsessionStorage\s*\.\s*getItem\s*\(")),
]

SANITIZER_PATTERNS = [
    re.compile(r"\bDOMPurify\s*\.\s*sanitize\s*\("),
    re.compile(r"\bsanitize[-_]?[Hh]tml\s*\("),
    re.compile(r"\bfilterXSS\s*\("),
    re.compile(r"\bhe\s*\.\s*encode\s*\("),
    re.compile(r"\bescapeHtml\s*\(", re.I),
    re.compile(r"\bencodeURIComponent\s*\("),
    re.compile(r"\bencodeURI\s*\("),
    re.compile(r"\b\w*[Ss]aniti[sz]e\w*\s*\("),
    re.compile(r"\b\w*[Ee]scape\w*\s*\("),
]

# cada sink: (nombre, kind, regex_que_matchea_justo_antes_del_punto_de_captura)
#   kind == "call"       -> el regex debe terminar justo antes del '(' de apertura
#   kind == "assign"     -> el regex debe terminar justo antes del '=' de asignación
SINKS = [
    ("innerHTML", "assign", re.compile(r"\.\s*innerHTML\s*(?<!=)=(?!=)")),
    ("outerHTML", "assign", re.compile(r"\.\s*outerHTML\s*(?<!=)=(?!=)")),
    ("document.write()", "call", re.compile(r"\bdocument\s*\.\s*write\s*\(")),
    ("document.writeln()", "call", re.compile(r"\bdocument\s*\.\s*writeln\s*\(")),
    ("insertAdjacentHTML()", "call", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("eval()", "call", re.compile(r"(?<![.\w])eval\s*\(")),
    ("new Function()", "call", re.compile(r"\bnew\s+Function\s*\(")),
    ("setTimeout() con string", "call", re.compile(r"\bsetTimeout\s*\(")),
    ("setInterval() con string", "call", re.compile(r"\bsetInterval\s*\(")),
    ("jQuery .html()", "call", re.compile(r"\$\([^)]{0,120}\)\s*\.\s*html\s*\(")),
    ("dangerouslySetInnerHTML (React)", "object", re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{")),
    ("location = / location.href =", "assign", re.compile(r"\blocation(?:\s*\.\s*href)?\s*(?<!=)=(?!=)")),
    ("element.src =", "assign", re.compile(r"\.\s*src\s*(?<!=)=(?!=)")),
    ("setAttribute(href/src, ...)", "call", re.compile(r"\.\s*setAttribute\s*\(\s*['\"](?:href|src)['\"]\s*,")),
]

VAR_ASSIGN_RE_TMPL = r"(?:\bvar\b|\blet\b|\bconst\b)?\s*\b{name}\b\s*(?<!=)=(?!=)"

MAX_SNIPPET = 200


def _has_source(text):
    for name, pat in SOURCE_PATTERNS:
        if pat.search(text):
            return name
    return None


def _has_sanitizer(text):
    for pat in SANITIZER_PATTERNS:
        if pat.search(text):
            return True
    return False


def _line_of(clean, idx):
    return clean.count("\n", 0, idx) + 1


def _snippet(text):
    text = " ".join(text.split())
    return text if len(text) <= MAX_SNIPPET else text[: MAX_SNIPPET - 3] + "..."


def analyze_taint(src, source_name):
    """Corre el motor de sinks/fuentes/sanitizadores sobre un archivo JS y
    devuelve una lista de hallazgos de flujo DOM-XSS."""
    clean = strip_comments_preserve_offsets(src)
    code_only = mask_string_contents(clean)  # + contenido literal de strings en blanco
    findings = []

    for sink_name, kind, pat in SINKS:
        for m in pat.finditer(code_only):
            end = m.end()

            if kind == "call":
                open_paren = code_only.find("(", end - 1)
                if open_paren == -1 or code_only[end - 1] != "(":
                    open_paren = end - 1
                arg_text, arg_end = extract_call_args(code_only, open_paren)

                if sink_name in ("setTimeout() con string", "setInterval() con string"):
                    first_arg = arg_text.split(",")[0].strip()
                    if not first_arg or first_arg[:1] not in "\"'`":
                        continue  # es una referencia a función, no un string interpolado: no es sink

                expr = arg_text
                expr_display = clean[open_paren + 1: arg_end - 1]
            elif kind == "assign":
                eq_pos = end
                expr, expr_end = extract_rhs(code_only, eq_pos)
                expr_display = clean[eq_pos:expr_end].strip()
            else:  # object -> dangerouslySetInnerHTML={{ ... }}
                brace_pos = code_only.find("{{", m.start())
                open_paren = brace_pos + 1 if brace_pos != -1 else end
                expr, arg_end = extract_call_args(code_only, open_paren)
                expr_display = clean[open_paren + 1: arg_end - 1]

            if not expr.strip():
                continue

            line = _line_of(clean, m.start())
            source_hit = _has_source(expr)
            sanitized_here = _has_sanitizer(expr)

            if source_hit:
                severity = "low" if sanitized_here else "critical"
                label = f"{sink_name} <- {source_hit}" + (" (parece sanitizado, verificar)" if sanitized_here else "")
                findings.append({
                    "category": "dom-xss", "severity": severity, "sink": sink_name,
                    "source": source_hit, "sanitized": sanitized_here,
                    "confidence": "alta (fuente y sink en la misma expresión)",
                    "label": label, "line": line, "value": _snippet(expr_display),
                    "source_file": source_name,
                })
                continue

            bare_var = re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", expr.strip())
            if bare_var:
                var_name = expr.strip()
                assign_re = re.compile(VAR_ASSIGN_RE_TMPL.format(name=re.escape(var_name)))
                last_match = None
                for am in assign_re.finditer(code_only, 0, m.start()):
                    last_match = am
                if last_match:
                    rhs, rhs_end = extract_rhs(code_only, last_match.end())
                    rhs_display = clean[last_match.end():rhs_end].strip()
                    src_hit2 = _has_source(rhs)
                    if src_hit2:
                        sanitized2 = _has_sanitizer(rhs)
                        severity = "low" if sanitized2 else "high"
                        label = (f"{sink_name} <- variable '{var_name}' <- {src_hit2}"
                                  + (" (parece sanitizado, verificar)" if sanitized2 else ""))
                        findings.append({
                            "category": "dom-xss", "severity": severity, "sink": sink_name,
                            "source": src_hit2, "sanitized": sanitized2,
                            "confidence": "media (taint de variable, 1 salto, sin análisis de scope real)",
                            "label": label, "line": line,
                            "value": f"{var_name} = {_snippet(rhs_display)}",
                            "source_file": source_name,
                        })
                        continue

            if sink_name in ("eval()", "new Function()", "document.write()", "document.writeln()"):
                findings.append({
                    "category": "dom-xss", "severity": "info", "sink": sink_name,
                    "source": None, "sanitized": False,
                    "confidence": "baja (sink de alto riesgo, fuente no identificada automáticamente)",
                    "label": f"{sink_name} — revisar manualmente de dónde viene el argumento",
                    "line": line, "value": _snippet(expr_display), "source_file": source_name,
                })

    seen = {}
    deduped = []
    for f in findings:
        key = (f["sink"], f["line"], f["value"])
        if key in seen:
            continue
        seen[key] = True
        deduped.append(f)
    return deduped


# ============================================================================
# CRAWLER — igual estrategia que JSHunter (misma home, mismo crawl de
# enlaces internos, mismas rutas comunes, mismos sourcemaps). Se reimplementa
# acá para que DOMXRay no dependa de importar el archivo de JSHunter.
# ============================================================================

USER_AGENT = "Mozilla/5.0 (compatible; DOMXRay/1.0; +recon-tool)"
TIMEOUT = 10
MAX_JS_SIZE = 5 * 1024 * 1024
MAX_MAP_SIZE = 10 * 1024 * 1024

SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

COMMON_JS_PATHS = [
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/assets/js/main.js", "/assets/js/app.js", "/assets/bundle.js",
    "/js/app.js", "/js/main.js", "/dist/main.js", "/dist/bundle.js",
    "/build/main.js", "/main.js", "/app.js", "/bundle.js", "/config.js",
]


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script_srcs = []
        self.anchors = []
        self._in_inline_script = False
        self._inline_buf = []
        self.inline_blocks = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "script":
            src = attr_dict.get("src")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_inline_script = True
                self._inline_buf = []
        elif tag == "a":
            href = attr_dict.get("href")
            if href:
                self.anchors.append(href)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_inline_script:
            self._in_inline_script = False
            if self._inline_buf:
                self.inline_blocks.append("".join(self._inline_buf))

    def handle_data(self, data):
        if self._in_inline_script:
            self._inline_buf.append(data)


class RateLimiter:
    def __init__(self, delay):
        self.delay = delay
        self.last_request = {}

    def wait(self, host):
        if self.delay <= 0:
            return
        last = self.last_request.get(host)
        if last is not None:
            elapsed = time.time() - last
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self.last_request[host] = time.time()


def fetch(url, max_size=None, limiter=None):
    if limiter is not None:
        limiter.wait(urllib.parse.urlparse(url).netloc)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(max_size + 1 if max_size else None)
        charset = resp.headers.get_content_charset() or "utf-8"
        return data.decode(charset, errors="replace")


def try_fetch(url, max_size=None, limiter=None):
    try:
        return fetch(url, max_size=max_size, limiter=limiter)
    except Exception:
        return None


def extract_sourcemap_sources(js_url, js_content, limiter=None):
    out = []
    m = SOURCEMAP_COMMENT_RE.search(js_content)
    candidates = []
    if m:
        candidates.append(urllib.parse.urljoin(js_url, m.group(1)))
    candidates.append(js_url + ".map")

    for map_url in candidates:
        try:
            raw = fetch(map_url, max_size=MAX_MAP_SIZE, limiter=limiter)
            data = json.loads(raw)
        except Exception:
            continue
        sources = data.get("sources", [])
        contents = data.get("sourcesContent", [])
        if not contents:
            continue
        for i, content in enumerate(contents):
            if not content:
                continue
            fname = sources[i] if i < len(sources) else f"source-{i}"
            out.append((f"{map_url} :: {fname}", content))
        break
    return out


def normalize_domain(d):
    d = d.strip()
    if not d or d.startswith("#"):
        return None
    if not d.startswith("http://") and not d.startswith("https://"):
        d = "https://" + d
    return d


def fetch_page_with_fallback(url, limiter=None):
    try:
        return fetch(url, limiter=limiter), url
    except Exception:
        alt = url.replace("https://", "http://") if url.startswith("https://") else url.replace("http://", "https://")
        content = fetch(alt, limiter=limiter)
        return content, alt


def discover_js_urls(base_url, verbose=False, depth=1, max_pages=10,
                      common_paths=True, sourcemaps=True, limiter=None):
    sources = []
    js_urls_seen = set()
    pages_seen = set()
    pages_to_visit = [(base_url, 0)]
    origin = urllib.parse.urlparse(base_url).netloc
    fetched_pages = 0

    def collect_scripts_from(page_url, html):
        parser = PageParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        for i, block in enumerate(parser.inline_blocks):
            if block.strip():
                sources.append((f"{page_url} [inline#{i}]", block))

        for src in parser.script_srcs:
            full_url = urllib.parse.urljoin(page_url, src)
            if full_url in js_urls_seen:
                continue
            js_urls_seen.add(full_url)
            try:
                content = fetch(full_url, max_size=MAX_JS_SIZE, limiter=limiter)
                sources.append((full_url, content))
                if sourcemaps:
                    sources.extend(extract_sourcemap_sources(full_url, content, limiter=limiter))
            except Exception as e:
                if verbose:
                    print(f"  [!] no se pudo descargar {full_url}: {e}", file=sys.stderr)

        return parser.anchors

    real_base = base_url
    while pages_to_visit and fetched_pages < max_pages:
        page_url, page_depth = pages_to_visit.pop(0)
        if page_url in pages_seen:
            continue
        pages_seen.add(page_url)

        try:
            html, resolved_url = fetch_page_with_fallback(page_url, limiter=limiter)
            if page_url == base_url:
                real_base = resolved_url
        except Exception as e:
            if verbose:
                print(f"  [!] no se pudo acceder a {page_url}: {e}", file=sys.stderr)
            continue

        fetched_pages += 1
        anchors = collect_scripts_from(resolved_url, html)

        if page_depth < depth:
            for href in anchors:
                full = urllib.parse.urljoin(resolved_url, href)
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc != origin:
                    continue
                if parsed.scheme not in ("http", "https"):
                    continue
                clean_url = parsed._replace(fragment="").geturl()
                if clean_url not in pages_seen:
                    pages_to_visit.append((clean_url, page_depth + 1))

    if common_paths:
        for path in COMMON_JS_PATHS:
            full_url = urllib.parse.urljoin(real_base, path)
            if full_url in js_urls_seen:
                continue
            js_urls_seen.add(full_url)
            content = try_fetch(full_url, max_size=MAX_JS_SIZE, limiter=limiter)
            if content is not None:
                sources.append((full_url, content))
                if sourcemaps:
                    sources.extend(extract_sourcemap_sources(full_url, content, limiter=limiter))

    return sources


# ============================================================================
# CLI / REPORTE
# ============================================================================

SEV_COLOR = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m",
             "low": "\033[92m", "info": "\033[96m"}
RESET = "\033[0m"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL_ES = {"critical": "crítico", "high": "alto", "medium": "medio", "low": "bajo", "info": "info"}


def process_domain(domain_raw, verbose=False, depth=1, max_pages=10,
                    common_paths=True, sourcemaps=True, limiter=None):
    base_url = normalize_domain(domain_raw)
    if not base_url:
        return domain_raw, [], 0
    sources = discover_js_urls(
        base_url, verbose=verbose, depth=depth, max_pages=max_pages,
        common_paths=common_paths, sourcemaps=sourcemaps, limiter=limiter,
    )
    all_findings = []
    for name, content in sources:
        all_findings.extend(analyze_taint(content, name))
    return base_url, all_findings, len(sources)


def _html_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


def build_html_report(report, output_path):
    total_findings = sum(len(v) for v in report.values())
    total_critical = sum(1 for v in report.values() for f in v if f["severity"] in ("critical", "high"))

    domain_blocks = []
    for domain, findings in report.items():
        if not findings:
            domain_blocks.append(f"""
            <section class="domain">
              <h2>{_html_escape(domain)} <span class="count">0 hallazgos</span></h2>
            </section>""")
            continue

        findings_sorted = sorted(findings, key=lambda f: SEV_ORDER[f["severity"]])
        rows = "\n".join(f"""
          <div class="row">
            <span class="badge {f['severity']}">{SEV_LABEL_ES[f['severity']]}</span>
            <span class="label">{_html_escape(f['sink'])}</span>
            <span class="src2">{_html_escape(f['source'] or '—')}</span>
            <span class="val">L{f['line']}: {_html_escape(f['value'][:130])}</span>
            <span class="src">{_html_escape(f['source_file'])[:90]}</span>
          </div>""" for f in findings_sorted)

        crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        domain_blocks.append(f"""
        <section class="domain">
          <h2>{_html_escape(domain)} <span class="count">{len(findings)} hallazgos{f' · {crit} críticos/altos' if crit else ''}</span></h2>
          <div class="rows">{rows}</div>
        </section>""")

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>DOMXRay — reporte</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{{--void:#0B0F12;--panel:#12181C;--border:#232C31;--text:#E8ECEE;--muted:#7C8A90;
         --dim:#4F5B60;--amber:#F0A868;--cyan:#5FB3C7;--danger:#E0605A;--ok:#6FAE7D;}}
  *{{box-sizing:border-box;}}
  body{{background:var(--void);color:var(--text);font-family:'Space Grotesk',sans-serif;margin:0;padding:28px;}}
  h1{{font-size:20px;margin:0 0 4px;}}
  .meta{{color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:12.5px;margin-bottom:28px;}}
  .meta b{{color:var(--danger);}}
  .domain{{margin-bottom:22px;border:1px solid var(--border);border-radius:10px;overflow:hidden;}}
  .domain h2{{font-size:14px;margin:0;padding:12px 16px;background:var(--panel);border-bottom:1px solid var(--border);
              display:flex;justify-content:space-between;font-weight:600;}}
  .count{{color:var(--muted);font-family:'JetBrains Mono',monospace;font-weight:400;font-size:11.5px;}}
  .row{{display:flex;gap:10px;align-items:center;padding:8px 16px;border-bottom:1px solid #1B2226;
        font-family:'JetBrains Mono',monospace;font-size:11.5px;}}
  .row:last-child{{border-bottom:none;}}
  .badge{{flex-shrink:0;font-size:9.5px;font-weight:600;padding:2px 6px;border-radius:4px;text-transform:uppercase;width:52px;text-align:center;}}
  .badge.critical{{background:rgba(224,96,90,.15);color:var(--danger);}}
  .badge.high{{background:rgba(224,96,90,.15);color:var(--danger);}}
  .badge.medium{{background:rgba(240,168,104,.15);color:var(--amber);}}
  .badge.low{{background:rgba(111,174,125,.15);color:var(--ok);}}
  .badge.info{{background:rgba(95,179,199,.15);color:var(--cyan);}}
  .label{{flex-shrink:0;color:var(--amber);width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
  .src2{{flex-shrink:0;color:var(--cyan);width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
  .val{{flex:2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
  .src{{flex:1;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;}}
</style></head>
<body>
  <h1>DOMXRay — reporte de flujos DOM-XSS</h1>
  <div class="meta">{len(report)} dominio(s) · <b>{total_findings}</b> hallazgos totales · <b>{total_critical}</b> críticos/altos</div>
  {"".join(domain_blocks)}
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)


def main():
    ap = argparse.ArgumentParser(description="DOMXRay — analizador de taint-flow DOM-XSS")
    ap.add_argument("-d", "--domain", action="append", default=[], help="dominio único (repetible)")
    ap.add_argument("-l", "--list", help="archivo con lista de dominios, uno por línea")
    ap.add_argument("-f", "--file", action="append", default=[], help="analizar un archivo .js local (repetible), sin crawlear")
    ap.add_argument("-o", "--output", default="domxray-report.json", help="archivo JSON de salida")
    ap.add_argument("--html", metavar="ARCHIVO.html", help="además, genera un reporte visual HTML")
    ap.add_argument("--threads", type=int, default=6, help="dominios en paralelo (default: 6)")
    ap.add_argument("--depth", type=int, default=1, help="niveles de enlaces internos a seguir (default: 1)")
    ap.add_argument("--max-pages", type=int, default=10, help="máximo de páginas por dominio (default: 10)")
    ap.add_argument("--delay", type=float, default=0.2, help="segundos mínimos entre requests al mismo host (default: 0.2)")
    ap.add_argument("--no-common-paths", action="store_true", help="no probar rutas JS comunes no enlazadas")
    ap.add_argument("--no-sourcemaps", action="store_true", help="no buscar/descargar sourcemaps")
    ap.add_argument("-v", "--verbose", action="store_true", help="mostrar errores de descarga")
    args = ap.parse_args()

    report = {}

    if args.file:
        for path in args.file:
            try:
                with open(path, "r", errors="replace") as fh:
                    content = fh.read()
            except Exception as e:
                print(f"[!] no se pudo leer {path}: {e}", file=sys.stderr)
                continue
            findings = analyze_taint(content, path)
            report[path] = findings
            crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
            print(f"[+] {path} — {len(findings)} hallazgo(s)"
                  + (f" · {SEV_COLOR['critical']}{crit} crítico(s)/alto(s){RESET}" if crit else ""))
            for f in sorted(findings, key=lambda x: SEV_ORDER[x["severity"]])[:30]:
                color = SEV_COLOR[f["severity"]]
                print(f"      {color}{f['severity']:<9}{RESET} L{f['line']:<5} {f['label']}")

    domains = list(args.domain)
    if args.list:
        with open(args.list) as f:
            domains.extend(line.strip() for line in f if line.strip())

    if domains:
        print(f"[*] {len(domains)} dominio(s) en cola · {args.threads} en paralelo · "
              f"profundidad {args.depth} · hasta {args.max_pages} páginas/dominio")
        print("[*] recuerda: solo contra objetivos que tengas autorización para probar\n")

        limiter = RateLimiter(args.delay)
        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {
                pool.submit(
                    process_domain, d,
                    verbose=args.verbose, depth=args.depth, max_pages=args.max_pages,
                    common_paths=not args.no_common_paths, sourcemaps=not args.no_sourcemaps,
                    limiter=limiter,
                ): d for d in domains
            }
            for fut in concurrent.futures.as_completed(futures):
                domain_raw = futures[fut]
                try:
                    base_url, findings, n_sources = fut.result()
                except Exception as e:
                    print(f"[!] error en {domain_raw}: {e}", file=sys.stderr)
                    continue

                report[base_url] = findings
                crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
                print(f"[+] {base_url} — {n_sources} archivo(s) JS · {len(findings)} hallazgo(s)"
                      + (f" · {SEV_COLOR['critical']}{crit} crítico(s)/alto(s){RESET}" if crit else ""))

                for f in sorted(findings, key=lambda x: SEV_ORDER[x["severity"]])[:20]:
                    color = SEV_COLOR[f["severity"]]
                    print(f"      {color}{f['severity']:<9}{RESET} L{f['line']:<5} {f['label']}")
                if len(findings) > 20:
                    print(f"      ... y {len(findings) - 20} más (ver JSON)")

        elapsed = time.time() - t0
        print(f"\n[*] listo en {elapsed:.1f}s")

    if not domains and not args.file:
        ap.error("dame al menos un dominio (-d/-l) o un archivo local (-f)")

    total_findings = sum(len(v) for v in report.values())
    total_critical = sum(1 for v in report.values() for f in v if f["severity"] in ("critical", "high"))

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[*] {total_findings} hallazgos totales ({total_critical} críticos/altos) — guardado en {args.output}")

    if args.html:
        build_html_report(report, args.html)
        print(f"[*] reporte visual guardado en {args.html}")


if __name__ == "__main__":
    main()
