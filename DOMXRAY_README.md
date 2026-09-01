# DOMXRay

Hermano de JSHunter: mismo estilo (Python puro, sin dependencias, mismo crawler), pero motor de detección distinto — en vez de buscar *strings sospechosos* (secretos, endpoints), rastrea **flujos de datos peligrosos**:

```
fuente no confiable (location.hash, document.cookie, postMessage, ...)
    --> llega sin sanitizar -->
sink peligroso (innerHTML, eval, document.write, insertAdjacentHTML, ...)
```

## Uso

```bash
# un dominio (crawlea igual que JSHunter: home, enlaces internos, rutas comunes, sourcemaps)
python3 domxray.py -d ejemplo.com

# lista de dominios + reporte visual
python3 domxray.py -l dominios.txt --html reporte.html

# archivo(s) .js locales, sin crawlear (útil si ya tienes el JS capturado con Burp)
python3 domxray.py -f app.js -f vendor.js

# más profundo / más lento y respetuoso
python3 domxray.py -d ejemplo.com --depth 2 --max-pages 15 --delay 0.5
```

Mismas flags que JSHunter CLI (`--threads`, `--depth`, `--max-pages`, `--delay`, `--no-common-paths`, `--no-sourcemaps`, `-o`, `--html`, `-v`), más `-f/--file` para analizar JS local sin red.

## Qué detecta

**Sinks:** `innerHTML`/`outerHTML =`, `document.write()`/`writeln()`, `insertAdjacentHTML()`, `eval()`, `new Function()`, `setTimeout()`/`setInterval()` con string interpolado, jQuery `.html()`, `dangerouslySetInnerHTML` (React), `location =`/`location.href =`, `element.src =`, `setAttribute('href'/'src', ...)`.

**Fuentes:** `location.hash/search/href/pathname`, `document.location/referrer/URL/cookie`, `window.name`, `event.data` (postMessage), `URLSearchParams`/`.searchParams.get()`, `localStorage`/`sessionStorage.getItem()`.

**Sanitizadores reconocidos** (bajan la severidad a `low`): `DOMPurify.sanitize`, `sanitizeHtml`, `filterXSS`, `he.encode`, `escapeHtml`, `encodeURIComponent`/`encodeURI`, y cualquier función cuyo nombre contenga "sanitize" o "escape".

## Cómo evita falsos positivos

Igual que el lexer de JSHunter, pero en dos capas:

1. **Comentarios en blanco** — un sink escrito en un comentario (`// el.innerHTML = location.hash`) no dispara nada.
2. **Contenido de strings en blanco** — un sink mencionado como texto dentro de un string (`"no hagas el.innerHTML = location.hash"`) tampoco. Lo único que queda "vivo" dentro de un template literal es lo que va dentro de `${...}` (interpolación real de código), así que `` `<div>${location.hash}</div>` `` sí se detecta correctamente como innerHTML con fuente.

## Niveles de confianza

| Severidad | Cuándo |
|---|---|
| `critical` | Fuente y sink en la **misma expresión**, sin sanitizador detectado |
| `high` | Fuente llega al sink **a través de una variable** (1 salto: `var x = location.hash; ...; el.innerHTML = x;`), sin sanitizador |
| `low` | Fuente detectada pero con sanitizador presente en la misma expresión/asignación — probablemente seguro, pero **verificar manualmente** (los sanitizadores mal usados también fallan) |
| `info` | Sink de alto riesgo (`eval`, `document.write`, `new Function`) donde no se pudo identificar automáticamente el origen del dato — igual vale la pena revisarlo a mano |

## Limitaciones (léelas antes de confiar ciegamente en el output)

- El taint tracking de variables es de **1 salto** y sin análisis de scope real (no diferencia dos funciones distintas con una variable del mismo nombre). Si el dato pasa por dos o más variables intermedias antes del sink, no lo va a encontrar.
- No sigue el flujo entre archivos JS distintos ni a través de funciones (`function f(x){ el.innerHTML = x } f(location.hash)` no se detecta).
- Es heurística basada en patrones de texto, no un parser real ni un analizador de flujo de datos como un AST. Puede haber falsos negativos en código muy ofuscado/minificado agresivamente, y en teoría algún falso positivo en patrones inusuales.
- Sirve para **priorizar dónde mirar a mano**, no como prueba definitiva de explotabilidad — cada hallazgo hay que confirmarlo probando el flujo real.
