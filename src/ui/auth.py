"""Controles mínimos de autenticação e sessão para UI em VPS.

Este módulo foi desenhado para ser acoplado a qualquer framework web
(Flask/FastAPI/Starlette) via chamadas explícitas.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional


class AuthError(Exception):
    """Erro genérico de autenticação."""


class SessionExpired(AuthError):
    """Sessão inexistente ou expirada."""


class _PasswordHasher:
    """Hasher com preferência para argon2 e fallback para bcrypt."""

    def __init__(self) -> None:
        self._mode = None
        self._argon_hasher = None
        self._bcrypt = None

        try:
            from argon2 import PasswordHasher  # type: ignore

            self._argon_hasher = PasswordHasher()
            self._mode = "argon2"
            return
        except Exception:
            pass

        try:
            import bcrypt  # type: ignore

            self._bcrypt = bcrypt
            self._mode = "bcrypt"
            return
        except Exception as exc:
            raise RuntimeError(
                "Nenhum hasher suportado disponível. Instale argon2-cffi ou bcrypt."
            ) from exc

    @property
    def mode(self) -> str:
        return str(self._mode)

    def hash_password(self, plain_password: str) -> str:
        if self._mode == "argon2":
            return self._argon_hasher.hash(plain_password)

        salt = self._bcrypt.gensalt(rounds=12)
        digest = self._bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return digest.decode("utf-8")

    def verify(self, password_hash: str, plain_password: str) -> bool:
        if self._mode == "argon2":
            try:
                return bool(self._argon_hasher.verify(password_hash, plain_password))
            except Exception:
                return False

        try:
            return bool(
                self._bcrypt.checkpw(
                    plain_password.encode("utf-8"), password_hash.encode("utf-8")
                )
            )
        except Exception:
            return False


@dataclass
class SessionData:
    username: str
    expires_at: float


class SessionManager:
    """Armazena sessões em memória com expiração curta."""

    def __init__(self, ttl_seconds: int = 900) -> None:
        self._ttl_seconds = ttl_seconds
        self._sessions: Dict[str, SessionData] = {}

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(48)
        self._sessions[token] = SessionData(
            username=username,
            expires_at=time.time() + self._ttl_seconds,
        )
        return token

    def validate(self, token: str) -> SessionData:
        self._purge_expired()
        session = self._sessions.get(token)
        if session is None or session.expires_at < time.time():
            self._sessions.pop(token, None)
            raise SessionExpired("Sessão inválida ou expirada")
        return session

    def logout(self, token: str) -> None:
        self._sessions.pop(token, None)

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [t for t, s in self._sessions.items() if s.expires_at < now]
        for token in expired:
            self._sessions.pop(token, None)


class AuthService:
    """Autenticação simples por usuário/senha hash + sessão curta."""

    def __init__(self, session_ttl_seconds: int = 900) -> None:
        self._username = os.getenv("UI_AUTH_USER", "")
        self._password_hash = os.getenv("UI_AUTH_PASSWORD_HASH", "")
        self._secret_key = os.getenv("UI_SESSION_SECRET", "")
        self._hasher = _PasswordHasher()
        self.sessions = SessionManager(ttl_seconds=session_ttl_seconds)

        if not self._username or not self._password_hash:
            raise RuntimeError(
                "Defina UI_AUTH_USER e UI_AUTH_PASSWORD_HASH no ambiente (.env)."
            )

        if len(self._secret_key) < 32:
            raise RuntimeError(
                "UI_SESSION_SECRET deve ter ao menos 32 caracteres aleatórios."
            )

    def authenticate(self, username: str, password: str) -> str:
        # Nunca logar credenciais aqui.
        if username != self._username:
            raise AuthError("Credenciais inválidas")

        if not self._hasher.verify(self._password_hash, password):
            raise AuthError("Credenciais inválidas")

        return self.sessions.create(username=username)

    def check_session(self, token: Optional[str]) -> SessionData:
        if not token:
            raise SessionExpired("Sessão ausente")
        return self.sessions.validate(token)

    def logout(self, token: Optional[str]) -> None:
        if token:
            self.sessions.logout(token)


def generate_password_hash(plain_password: str) -> str:
    """Utilitário para gerar hash inicial (argon2/bcrypt)."""
    return _PasswordHasher().hash_password(plain_password)
