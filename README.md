# Auditor_HTTP
Verificador de redirecionamento para HTTPS

<p align="center">
  <img src="https://img.shields.io/badge/Projeto-Etico%20Auditor-850e32?style=for-the-badge&logo=python&logoColor=white" />
</p>


# 🔒 Etico Auditor - Python

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)  
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![Security](https://img.shields.io/badge/Security-Ethical%20Hacking-red.svg)](#-aviso-legal)  

Um **auditor HTTP(s) leve e seguro**, criado para fins de **hacking ético** e aprendizado em **cibersegurança**.  
O script realiza uma auditoria **não-invasiva** em sites (apenas com permissão!) e exibe recomendações de boas práticas.

---

## 🚀 Funcionalidades
- 🔐 Verifica se o site força **HTTPS**
- 📜 Mostra versão **TLS** e dados do **certificado digital**
- 🛡️ Analisa **cabeçalhos de segurança** (CSP, HSTS, X-Frame-Options, etc.)
- 🍪 Inspeciona **cookies** e flags (`Secure`, `HttpOnly`, `SameSite`)
- 📄 Procura por arquivo de contato `security.txt`


## 🛠️ Requisitos

- Biblioteca:
  ```bash
  pip install requests

## Como usar 
### Clone este repositório e execute o script passando um domínio:
 - python etico_auditor.py https://seu-dominio.com

   # ⚠️ Aviso Legal
- ⚠️ Uso responsável
Este projeto é apenas para fins educacionais e laboratórios controlados.
- ❌ Não utilize em sites ou sistemas sem autorização explícita.
- ✅ Utilize em:
Seus próprios domínios
Labs intencionais (OWASP Juice Shop, DVWA, WebGoat, etc.)
