# Checklist mínimo de segurança para operação em VPS

## 1) Autenticação de UI
- [ ] Definir `UI_AUTH_USER` e `UI_AUTH_PASSWORD_HASH` no `.env`.
- [ ] Gerar hash com Argon2 (preferencial) ou bcrypt:
  - Exemplo (Python):
    ```python
    from src.ui.auth import generate_password_hash
    print(generate_password_hash("SENHA_FORTE"))
    ```
- [ ] Validar login e logout via `AuthService` (`src/ui/auth.py`).

## 2) Sessão curta e expiração
- [ ] Configurar `SESSION_TTL_SECONDS` para janela curta (ex.: 900s).
- [ ] Garantir invalidação de sessão no logout.
- [ ] Não reutilizar token de sessão após expiração.

## 3) HTTPS obrigatório (NGINX)
- [ ] Instalar certificados TLS válidos (ex.: Let's Encrypt).
- [ ] Aplicar `deploy/nginx.conf`.
- [ ] Validar redirecionamento `http://` -> `https://`.
- [ ] Validar `Strict-Transport-Security` habilitado.

## 4) Segredos em variáveis de ambiente
- [ ] Nunca versionar `.env` real; usar apenas `.env.example`.
- [ ] Definir `UI_SESSION_SECRET` (>=32 chars aleatórios).
- [ ] Não imprimir usuário/senha/token em logs.
- [ ] Revisar logs para garantir ausência de credenciais.

## 5) Serviços com hardening básico (systemd)
- [ ] Instalar `deploy/systemd/bg-ui.service`.
- [ ] Instalar `deploy/systemd/bg-ui-worker.service` (se houver worker).
- [ ] Executar com usuário dedicado sem privilégios (`bg`).
- [ ] Conferir flags: `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, etc.

## 6) Verificações operacionais pós-deploy
- [ ] `systemctl daemon-reload`
- [ ] `systemctl enable --now bg-ui.service`
- [ ] `systemctl status bg-ui.service`
- [ ] Testar acesso com e sem autenticação.
- [ ] Confirmar headers de segurança com `curl -I https://SEU_DOMINIO`.
