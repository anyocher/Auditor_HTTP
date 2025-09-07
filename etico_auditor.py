script_code = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditor HTTP seguro (somente com permissão)
- Verifica redirecionamento para HTTPS
- Coleta e avalia cabeçalhos de segurança
- Inspeciona flags de cookies (Secure, HttpOnly, SameSite)
- Mostra versão TLS e validade do certificado

Uso:
    python etico_auditor.py https://exemplo.com

IMPORTANTE:
- Execute SOMENTE em domínios/serviços que você possui ou tem permissão explícita por escrito.
- O script faz apenas requisições leves (GET e HEAD) e uma conexão TLS para leitura de certificado.
"""
import sys
import ssl
import socket
import json
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import re

try:
    import requests
except ImportError:
    print("Este script requer o pacote 'requests'. Instale com: pip install requests")
    sys.exit(1)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]


def normalize_url(url: str) -> str:
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'https://' + url  # preferimos HTTPS por padrão
    parsed = urlparse(url)
    # Remove fragmentos e normaliza caminho vazio para '/'
    path = parsed.path if parsed.path else '/'
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, '', '', ''))


def fetch(url: str):
    ua = "EticoAuditor/1.0 (+permissao-necessaria)"
    try:
        resp = requests.get(url, headers={"User-Agent": ua}, timeout=10, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        return e


def assess_headers(headers: dict):
    present = {}
    missing = []
    notes = []

    # Normaliza chaves para acesso case-insensitive
    lower_map = {k.lower(): k for k in headers.keys()}
    for h in SECURITY_HEADERS:
        key_lower = h.lower()
        if key_lower in lower_map:
            present[h] = headers[lower_map[key_lower]]
        else:
            missing.append(h)

    # Checks simples de conteúdo
    if "Strict-Transport-Security" in present:
        if "max-age" not in present["Strict-Transport-Security"]:
            notes.append("HSTS presente mas sem max-age.")
    if "Content-Security-Policy" in present:
        csp = present["Content-Security-Policy"]
        if "default-src" not in csp:
            notes.append("CSP presente, considere definir default-src.")
    if "X-Content-Type-Options" in present and present["X-Content-Type-Options"].lower() != "nosniff":
        notes.append("X-Content-Type-Options deve ser 'nosniff'.")
    if "X-Frame-Options" in present and present["X-Frame-Options"].lower() not in ("deny", "sameorigin"):
        notes.append("X-Frame-Options idealmente 'DENY' ou 'SAMEORIGIN'.")

    return present, missing, notes


def parse_cookie_flags(set_cookie_headers):
    cookies_info = []
    if not set_cookie_headers:
        return cookies_info

    if isinstance(set_cookie_headers, str):
        set_cookie_headers = [set_cookie_headers]

    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        flags = {p.lower(): True for p in parts[1:]}
        cookies_info.append({
            "cookie": name_val,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": next((p.split("=")[1] for p in parts[1:] if p.strip().lower().startswith("samesite=")), None)
        })
    return cookies_info


def tls_info(hostname: str, port: int = 443):
    context = ssl.create_default_context()
    info = {
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_not_before": None,
        "cert_not_after": None,
        "days_to_expire": None,
        "alpn_protocol": None,
    }
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["tls_version"] = ssock.version()
                info["alpn_protocol"] = ssock.selected_alpn_protocol()
                cert = ssock.getpeercert()
                if cert:
                    info["cert_subject"] = dict(x[0] for x in cert.get('subject', ())).get('commonName')
                    info["cert_issuer"] = dict(x[0] for x in cert.get('issuer', ())).get('commonName')
                    # datas no formato 'Jun  1 12:00:00 2025 GMT'
                    nb_str = cert.get('notBefore')
                    na_str = cert.get('notAfter')
                    dt_fmt = r"%b %d %H:%M:%S %Y %Z"
                    if nb_str:
                        info["cert_not_before"] = nb_str
                    if na_str:
                        info["cert_not_after"] = na_str
                        try:
                            dt_na = datetime.strptime(na_str, dt_fmt)
                            delta = dt_na - datetime.utcnow()
                            info["days_to_expire"] = delta.days
                        except Exception:
                            pass
    except Exception as e:
        info["error"] = str(e)
    return info


def check_security_txt(base_url: str):
    # Busca /.well-known/security.txt (GET)
    try:
        parsed = urlparse(base_url)
        sec_url = urlunparse((parsed.scheme, parsed.netloc, "/.well-known/security.txt", '', '', ''))
        r = requests.get(sec_url, timeout=8, headers={"User-Agent": "EticoAuditor/1.0"})
        return {"url": sec_url, "status": r.status_code, "found": r.ok, "preview": r.text[:300] if r.ok else ""}
    except requests.RequestException as e:
        return {"error": str(e)}


def main():
    if len(sys.argv) != 2:
        print("Uso: python etico_auditor.py https://seu-dominio.com")
        sys.exit(2)

    raw_url = sys.argv[1]
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]

    print("[i] Verificando:", url)

    # Requisição principal (seguindo redirecionamentos)
    resp = fetch(url)
    if isinstance(resp, Exception):
        print("[!] Erro ao requisitar a URL:", resp)
        sys.exit(1)

    final_url = resp.url
    scheme = urlparse(final_url).scheme
    redirected = (final_url != url)

    print(f"[i] Status final: {resp.status_code}")
    print(f"[i] URL final: {final_url}")
    print(f"[i] Redirecionado: {redirected}")
    print(f"[i] HTTPS: {scheme == 'https'}")

    # TLS
    if scheme == "https":
        print("\n=== TLS/Certificado ===")
        tinfo = tls_info(host)
        for k, v in tinfo.items():
            print(f"{k}: {v}")

    # Cabeçalhos
    print("\n=== Cabeçalhos de segurança ===")
    present, missing, notes = assess_headers(resp.headers)
    for k, v in present.items():
        print(f"{k}: {v}")
    if missing:
        print("Faltando:", ", ".join(missing))
    if notes:
        print("Observações:")
        for n in notes:
            print("-", n)

    # Cookies
    print("\n=== Cookies (flags) ===")
    set_cookie = resp.headers.get("Set-Cookie")
    # requests agrupa só o primeiro; vamos pegar todos se existirem
    set_cookie_all = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw, "headers") else None
    cookies = parse_cookie_flags(set_cookie_all or set_cookie)
    if not cookies:
        print("Sem Set-Cookie no response.")
    else:
        for c in cookies:
            print(json.dumps(c, ensure_ascii=False))

    # security.txt
    print("\n=== security.txt ===")
    st = check_security_txt(final_url)
    print(json.dumps(st, ensure_ascii=False))

    print("\n[✔] Auditoria leve concluída. Lembre-se: use sempre com permissão e responsabilidade.")

if __name__ == "__main__":
    main()
'''

path = "/mnt/data/etico_auditor.py"
with open(path, "w", encoding="utf-8") as f:
    f.write(script_code)

print(f"Arquivo salvo em: {path}")
print("\nComo usar no terminal:\n")
print("python etico_auditor.py https://seu-dominio.com")

