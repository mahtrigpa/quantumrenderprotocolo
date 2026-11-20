#!/usr/bin/env python3
"""
Escaner de secretos expuestos. Sin IA, sin tokens, sin red.
Busca claves y tokens que no deberian estar en un repositorio. Sale con codigo 1 si encuentra
una ALERTA; los AVISOS se muestran pero no bloquean.
Uso: python3 seguridad/escaner_secretos.py [carpeta]

Limites: reconoce formatos comunes; no garantiza que no haya otros secretos. Si hay una ALERTA,
revoca la credencial en su proveedor: borrar el archivo no basta, queda en el historial de git.
Las claves web de Firebase (AIza... dentro de firebaseConfig) se tratan como AVISO: Google indica
que no son secretas; lo que las protege son las reglas de seguridad de Firebase y sus restricciones.
"""
import os, re, sys

GOOGLE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
PATRONES = [
    ("Token de GitHub", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("Token de GitHub (fine-grained)", r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    ("Clave estilo API (sk-)", r"\bsk-[A-Za-z0-9_-]{32,}\b"),
    ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Clave privada", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("Token de bot de Telegram", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("Asignacion de clave o secreto", r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{24,}['\"]"),
]
OMITIR_DIRS = {".git", "node_modules", ".venv", "__pycache__"}


def escanear(raiz):
    yo = os.path.abspath(__file__)
    alertas, avisos = [], []
    for d, dirs, archivos in os.walk(raiz):
        dirs[:] = [x for x in dirs if x not in OMITIR_DIRS]
        for f in archivos:
            ruta = os.path.join(d, f)
            if os.path.abspath(ruta) == yo or os.path.getsize(ruta) > 1_500_000:
                continue
            try:
                with open(ruta, "rb") as fh:
                    crudo = fh.read()
                if b"\x00" in crudo:
                    continue
                texto = crudo.decode("utf-8", errors="replace")
            except OSError:
                continue
            es_firebase = "firebaseConfig" in texto or "firebaseapp.com" in texto
            rel = os.path.relpath(ruta, raiz)
            for n, linea in enumerate(texto.splitlines(), 1):
                g = GOOGLE.search(linea)
                if g:
                    if es_firebase:
                        avisos.append((rel, n, "Clave web de Firebase", g.group(0)[:4] + "..."))
                    else:
                        alertas.append((rel, n, "Clave de API de Google", g.group(0)[:4] + "..."))
                    continue
                for nombre, pat in PATRONES:
                    m = re.search(pat, linea)
                    if m:
                        alertas.append((rel, n, nombre, m.group(0)[:4] + "..."))
                        break
    return alertas, avisos


if __name__ == "__main__":
    raiz = sys.argv[1] if len(sys.argv) > 1 else "."
    alertas, avisos = escanear(raiz)
    for ruta, n, nombre, prev in avisos:
        print(f"AVISO (no bloquea): {ruta}:{n}  {nombre} ({prev}). No es secreta por diseno; revisa las reglas de seguridad de Firebase y las restricciones de la clave.")
    if alertas:
        print(f"ALERTA: {len(alertas)} posible(s) secreto(s) expuesto(s):")
        for ruta, n, nombre, prev in alertas:
            print(f"  {ruta}:{n}  {nombre}  ({prev})")
        print("Revoca la credencial en su proveedor; borrar el archivo no basta (queda en el historial).")
        sys.exit(1)
    print("OK: sin alertas con los patrones conocidos." + (f" ({len(avisos)} aviso(s))" if avisos else ""))
