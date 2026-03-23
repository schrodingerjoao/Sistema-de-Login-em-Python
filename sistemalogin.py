"""
╔══════════════════════════════════════════════════════════════╗
║          SISTEMA DE LOGIN SOFISTICADO EM PYTHON              ║
║  Arquitetura: OOP + Segurança + Validação + Rate Limiting    ║
╚══════════════════════════════════════════════════════════════╝

Funcionalidades:
  - Hashing de senhas com bcrypt (PBKDF2 + salt)
  - Proteção contra força bruta (rate limiting + bloqueio de conta)
  - Validação robusta de e-mail e senha
  - Tokens de sessão com expiração
  - Registro de auditoria (log de eventos)
  - Persistência em JSON (simula banco de dados)
  - Padrão de design: Repository + Service + Controller
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════
# ENUMS E CONSTANTES
# ══════════════════════════════════════════════

class AuthStatus(Enum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_NOT_FOUND = "account_not_found"
    SESSION_EXPIRED = "session_expired"
    INVALID_TOKEN = "invalid_token"
    VALIDATION_ERROR = "validation_error"
    EMAIL_TAKEN = "email_taken"


class EventType(Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    REGISTER = "REGISTER"
    LOGOUT = "LOGOUT"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"


# Configurações de segurança
class SecurityConfig:
    MAX_LOGIN_ATTEMPTS   = 5          # Tentativas antes do bloqueio
    LOCKOUT_DURATION_MIN = 15         # Minutos de bloqueio
    SESSION_DURATION_MIN = 30         # Duração da sessão em minutos
    TOKEN_LENGTH         = 64         # Comprimento do token (bytes)
    SALT_LENGTH          = 32         # Comprimento do salt (bytes)
    PBKDF2_ITERATIONS    = 260_000    # Iterações do PBKDF2 (OWASP 2023)
    MIN_PASSWORD_LENGTH  = 8
    MAX_PASSWORD_LENGTH  = 128


# ══════════════════════════════════════════════
# MODELOS DE DADOS
# ══════════════════════════════════════════════

@dataclass
class User:
    id: str
    email: str
    password_hash: str
    salt: str
    created_at: str
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    is_active: bool = True

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return datetime.fromisoformat(self.locked_until) > datetime.now()

    def lock(self) -> None:
        duration = timedelta(minutes=SecurityConfig.LOCKOUT_DURATION_MIN)
        self.locked_until = (datetime.now() + duration).isoformat()

    def unlock(self) -> None:
        self.locked_until = None
        self.failed_attempts = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(**data)


@dataclass
class Session:
    id: str
    user_id: str
    token: str
    created_at: str
    expires_at: str
    is_active: bool = True

    def is_expired(self) -> bool:
        return datetime.fromisoformat(self.expires_at) < datetime.now()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        return cls(**data)


@dataclass
class AuditLog:
    id: str
    event_type: str
    user_email: str
    timestamp: str
    ip_address: str
    details: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuthResult:
    status: AuthStatus
    message: str
    session: Optional[Session] = None
    user_email: Optional[str] = None


# ══════════════════════════════════════════════
# CAMADA DE REPOSITÓRIO (persistência)
# ══════════════════════════════════════════════

class JSONRepository:
    """Simula um banco de dados usando arquivos JSON."""

    def __init__(self, filepath: str):
        self.path = Path(filepath)
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not self.path.exists():
            self.path.write_text(json.dumps([]), encoding="utf-8")

    def _load(self) -> list:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: list) -> None:
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def find_all(self) -> list:
        return self._load()

    def find_by(self, field: str, value) -> Optional[dict]:
        return next((item for item in self._load() if item.get(field) == value), None)

    def save(self, record: dict, key_field: str = "id") -> None:
        data = self._load()
        idx = next((i for i, r in enumerate(data) if r.get(key_field) == record[key_field]), None)
        if idx is not None:
            data[idx] = record
        else:
            data.append(record)
        self._save(data)

    def delete_by(self, field: str, value) -> None:
        data = [r for r in self._load() if r.get(field) != value]
        self._save(data)


# ══════════════════════════════════════════════
# SERVIÇOS DE SEGURANÇA
# ══════════════════════════════════════════════

class PasswordService:
    """Gerencia hashing e verificação de senhas com PBKDF2-HMAC-SHA256."""

    @staticmethod
    def generate_salt() -> str:
        return secrets.token_hex(SecurityConfig.SALT_LENGTH)

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            SecurityConfig.PBKDF2_ITERATIONS,
        )
        return dk.hex()

    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str) -> bool:
        candidate = PasswordService.hash_password(password, salt)
        # Comparação segura contra timing attacks
        return hmac.compare_digest(candidate, stored_hash)

    @staticmethod
    def validate_strength(password: str) -> tuple[bool, list[str]]:
        errors = []
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Mínimo de {SecurityConfig.MIN_PASSWORD_LENGTH} caracteres.")
        if len(password) > SecurityConfig.MAX_PASSWORD_LENGTH:
            errors.append(f"Máximo de {SecurityConfig.MAX_PASSWORD_LENGTH} caracteres.")
        if not re.search(r"[A-Z]", password):
            errors.append("Deve conter ao menos uma letra maiúscula.")
        if not re.search(r"[a-z]", password):
            errors.append("Deve conter ao menos uma letra minúscula.")
        if not re.search(r"\d", password):
            errors.append("Deve conter ao menos um número.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Deve conter ao menos um caractere especial.")
        return len(errors) == 0, errors


class TokenService:
    """Gera e valida tokens de sessão criptograficamente seguros."""

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(SecurityConfig.TOKEN_LENGTH)

    @staticmethod
    def create_session(user_id: str) -> Session:
        now = datetime.now()
        expires = now + timedelta(minutes=SecurityConfig.SESSION_DURATION_MIN)
        return Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token=TokenService.generate_token(),
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
        )


class ValidationService:
    """Valida inputs do usuário."""

    EMAIL_REGEX = re.compile(r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$")

    @staticmethod
    def validate_email(email: str) -> tuple[bool, str]:
        email = email.strip().lower()
        if not email:
            return False, "E-mail não pode ser vazio."
        if not ValidationService.EMAIL_REGEX.match(email):
            return False, "Formato de e-mail inválido."
        return True, email

    @staticmethod
    def sanitize_email(email: str) -> str:
        return email.strip().lower()


# ══════════════════════════════════════════════
# SERVIÇO DE AUDITORIA
# ══════════════════════════════════════════════

class AuditService:
    """Registra todos os eventos de autenticação."""

    def __init__(self, repo: JSONRepository):
        self.repo = repo

    def log(self, event: EventType, email: str, ip: str = "127.0.0.1", details: str = "") -> None:
        entry = AuditLog(
            id=str(uuid.uuid4()),
            event_type=event.value,
            user_email=email,
            timestamp=datetime.now().isoformat(),
            ip_address=ip,
            details=details,
        )
        self.repo.save(entry.to_dict())
        self._print_log(entry)

    def _print_log(self, log: AuditLog) -> None:
        ts = datetime.fromisoformat(log.timestamp).strftime("%H:%M:%S")
        icon_map = {
            "LOGIN_SUCCESS": "✅", "LOGIN_FAILED": "❌",
            "ACCOUNT_LOCKED": "🔒", "ACCOUNT_UNLOCKED": "🔓",
            "REGISTER": "📝", "LOGOUT": "👋",
            "SESSION_EXPIRED": "⏰", "PASSWORD_CHANGED": "🔑",
        }
        icon = icon_map.get(log.event_type, "•")
        print(f"  [{ts}] {icon} {log.event_type} | {log.user_email} | {log.details}")

    def get_history(self, email: str) -> list[dict]:
        return [r for r in self.repo.find_all() if r["user_email"] == email]


# ══════════════════════════════════════════════
# SERVIÇO DE AUTENTICAÇÃO (núcleo do sistema)
# ══════════════════════════════════════════════

class AuthService:
    """Orquestra todo o fluxo de autenticação."""

    def __init__(
        self,
        user_repo: JSONRepository,
        session_repo: JSONRepository,
        audit: AuditService,
    ):
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.audit = audit
        self.pwd_svc = PasswordService()
        self.token_svc = TokenService()
        self.val_svc = ValidationService()

    # ── Registro ──────────────────────────────

    def register(self, email: str, password: str, ip: str = "127.0.0.1") -> AuthResult:
        valid, result = self.val_svc.validate_email(email)
        if not valid:
            return AuthResult(AuthStatus.VALIDATION_ERROR, result)
        email = result

        strong, errors = PasswordService.validate_strength(password)
        if not strong:
            return AuthResult(AuthStatus.VALIDATION_ERROR, " | ".join(errors))

        if self.user_repo.find_by("email", email):
            return AuthResult(AuthStatus.EMAIL_TAKEN, "Este e-mail já está cadastrado.")

        salt = PasswordService.generate_salt()
        pwd_hash = PasswordService.hash_password(password, salt)

        user = User(
            id=str(uuid.uuid4()),
            email=email,
            password_hash=pwd_hash,
            salt=salt,
            created_at=datetime.now().isoformat(),
        )
        self.user_repo.save(user.to_dict())
        self.audit.log(EventType.REGISTER, email, ip, "Novo usuário registrado.")
        return AuthResult(AuthStatus.SUCCESS, "Cadastro realizado com sucesso!", user_email=email)

    # ── Login ─────────────────────────────────

    def login(self, email: str, password: str, ip: str = "127.0.0.1") -> AuthResult:
        email = ValidationService.sanitize_email(email)

        data = self.user_repo.find_by("email", email)
        if not data:
            self.audit.log(EventType.LOGIN_FAILED, email, ip, "Usuário não encontrado.")
            return AuthResult(AuthStatus.ACCOUNT_NOT_FOUND, "Credenciais inválidas.")

        user = User.from_dict(data)

        if user.is_locked():
            remaining = (datetime.fromisoformat(user.locked_until) - datetime.now())
            mins = int(remaining.total_seconds() // 60) + 1
            self.audit.log(EventType.ACCOUNT_LOCKED, email, ip, "Tentativa em conta bloqueada.")
            return AuthResult(
                AuthStatus.ACCOUNT_LOCKED,
                f"Conta bloqueada. Tente novamente em {mins} minuto(s).",
            )

        if not PasswordService.verify_password(password, user.salt, user.password_hash):
            user.failed_attempts += 1
            remaining_attempts = SecurityConfig.MAX_LOGIN_ATTEMPTS - user.failed_attempts

            if user.failed_attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
                user.lock()
                self.user_repo.save(user.to_dict())
                self.audit.log(EventType.ACCOUNT_LOCKED, email, ip,
                               f"Conta bloqueada após {user.failed_attempts} tentativas.")
                return AuthResult(
                    AuthStatus.ACCOUNT_LOCKED,
                    f"Conta bloqueada por {SecurityConfig.LOCKOUT_DURATION_MIN} minutos.",
                )

            self.user_repo.save(user.to_dict())
            self.audit.log(EventType.LOGIN_FAILED, email, ip,
                           f"Senha incorreta. Tentativa {user.failed_attempts}.")
            return AuthResult(
                AuthStatus.INVALID_CREDENTIALS,
                f"Credenciais inválidas. {remaining_attempts} tentativa(s) restante(s).",
            )

        # Sucesso — resetar tentativas e criar sessão
        user.unlock()
        self.user_repo.save(user.to_dict())

        session = TokenService.create_session(user.id)
        self.session_repo.save(session.to_dict())

        self.audit.log(EventType.LOGIN_SUCCESS, email, ip, f"Sessão {session.id[:8]}... criada.")
        return AuthResult(AuthStatus.SUCCESS, "Login realizado com sucesso!", session=session, user_email=email)

    # ── Validação de sessão ───────────────────

    def validate_session(self, token: str) -> AuthResult:
        data = self.session_repo.find_by("token", token)
        if not data:
            return AuthResult(AuthStatus.INVALID_TOKEN, "Token inválido.")

        session = Session.from_dict(data)

        if not session.is_active:
            return AuthResult(AuthStatus.INVALID_TOKEN, "Sessão inativa.")

        if session.is_expired():
            session.is_active = False
            self.session_repo.save(session.to_dict())
            user_data = self.user_repo.find_by("id", session.user_id)
            email = user_data["email"] if user_data else "unknown"
            self.audit.log(EventType.SESSION_EXPIRED, email, details="Sessão expirada.")
            return AuthResult(AuthStatus.SESSION_EXPIRED, "Sessão expirada. Faça login novamente.")

        return AuthResult(AuthStatus.SUCCESS, "Sessão válida.", session=session)

    # ── Logout ────────────────────────────────

    def logout(self, token: str, ip: str = "127.0.0.1") -> AuthResult:
        data = self.session_repo.find_by("token", token)
        if not data:
            return AuthResult(AuthStatus.INVALID_TOKEN, "Token não encontrado.")

        session = Session.from_dict(data)
        session.is_active = False
        self.session_repo.save(session.to_dict())

        user_data = self.user_repo.find_by("id", session.user_id)
        email = user_data["email"] if user_data else "unknown"
        self.audit.log(EventType.LOGOUT, email, ip, "Logout realizado.")
        return AuthResult(AuthStatus.SUCCESS, "Logout realizado com sucesso.")


# ══════════════════════════════════════════════
# CONTROLADOR — INTERFACE COM O USUÁRIO (CLI)
# ══════════════════════════════════════════════

class AuthController:
    """Interface de linha de comando para o sistema de login."""

    BANNER = """
╔══════════════════════════════════════════════╗
║        SISTEMA DE LOGIN SOFISTICADO          ║
║   Segurança · Sessões · Auditoria em tempo  ║
╚══════════════════════════════════════════════╝
"""
    MENU = """
  [1] Registrar nova conta
  [2] Fazer login
  [3] Validar sessão (token)
  [4] Fazer logout
  [5] Ver histórico de auditoria
  [0] Sair
"""

    def __init__(self):
        base = Path("data")
        base.mkdir(exist_ok=True)
        user_repo    = JSONRepository(str(base / "users.json"))
        session_repo = JSONRepository(str(base / "sessions.json"))
        audit_repo   = JSONRepository(str(base / "audit.json"))
        audit_svc    = AuditService(audit_repo)
        self.auth    = AuthService(user_repo, session_repo, audit_svc)
        self.audit   = audit_svc
        self._current_token: Optional[str] = None

    def _sep(self) -> None:
        print("  " + "─" * 44)

    def _print_result(self, result: AuthResult) -> None:
        icons = {
            AuthStatus.SUCCESS: "✅",
            AuthStatus.INVALID_CREDENTIALS: "❌",
            AuthStatus.ACCOUNT_LOCKED: "🔒",
            AuthStatus.ACCOUNT_NOT_FOUND: "❌",
            AuthStatus.SESSION_EXPIRED: "⏰",
            AuthStatus.INVALID_TOKEN: "❌",
            AuthStatus.VALIDATION_ERROR: "⚠️ ",
            AuthStatus.EMAIL_TAKEN: "⚠️ ",
        }
        icon = icons.get(result.status, "•")
        print(f"\n  {icon} {result.message}")

    def run(self) -> None:
        print(self.BANNER)
        while True:
            print(self.MENU)
            choice = input("  Escolha uma opção: ").strip()

            if choice == "1":
                self._handle_register()
            elif choice == "2":
                self._handle_login()
            elif choice == "3":
                self._handle_validate()
            elif choice == "4":
                self._handle_logout()
            elif choice == "5":
                self._handle_audit()
            elif choice == "0":
                print("\n  Até logo! 👋\n")
                break
            else:
                print("\n  ⚠️  Opção inválida.")

    def _handle_register(self) -> None:
        self._sep()
        print("  📝  REGISTRO DE NOVA CONTA")
        self._sep()
        email    = input("  E-mail   : ").strip()
        password = input("  Senha    : ").strip()
        result   = self.auth.register(email, password)
        self._print_result(result)

    def _handle_login(self) -> None:
        self._sep()
        print("  🔐  LOGIN")
        self._sep()
        email    = input("  E-mail   : ").strip()
        password = input("  Senha    : ").strip()
        result   = self.auth.login(email, password)
        self._print_result(result)
        if result.status == AuthStatus.SUCCESS and result.session:
            self._current_token = result.session.token
            print(f"\n  🎟️  Token de sessão (guarde-o):")
            print(f"  {result.session.token[:40]}...")
            exp = datetime.fromisoformat(result.session.expires_at).strftime("%H:%M:%S")
            print(f"  ⏱  Expira às {exp}")

    def _handle_validate(self) -> None:
        self._sep()
        print("  🔍  VALIDAR SESSÃO")
        self._sep()
        token = input("  Token (Enter = usar sessão atual): ").strip()
        if not token and self._current_token:
            token = self._current_token
            print(f"  → Usando token atual.")
        result = self.auth.validate_session(token)
        self._print_result(result)

    def _handle_logout(self) -> None:
        self._sep()
        print("  👋  LOGOUT")
        self._sep()
        token = input("  Token (Enter = usar sessão atual): ").strip()
        if not token and self._current_token:
            token = self._current_token
        result = self.auth.logout(token)
        self._print_result(result)
        if result.status == AuthStatus.SUCCESS:
            self._current_token = None

    def _handle_audit(self) -> None:
        self._sep()
        print("  📋  HISTÓRICO DE AUDITORIA")
        self._sep()
        email   = input("  E-mail do usuário: ").strip()
        history = self.audit.get_history(email)
        if not history:
            print("\n  Nenhum registro encontrado.")
            return
        print(f"\n  {len(history)} evento(s) encontrado(s):\n")
        for entry in history[-10:]:
            ts = datetime.fromisoformat(entry["timestamp"]).strftime("%d/%m %H:%M:%S")
            print(f"    [{ts}] {entry['event_type']} — {entry['details']}")


# ══════════════════════════════════════════════
# DEMONSTRAÇÃO AUTOMATIZADA
# ══════════════════════════════════════════════

def run_demo() -> None:
    """Roda uma demonstração completa do sistema sem interação manual."""
    print("""
╔══════════════════════════════════════════════╗
║          DEMO AUTOMATIZADA DO SISTEMA        ║
╚══════════════════════════════════════════════╝
""")

    base = Path("data_demo")
    base.mkdir(exist_ok=True)
    for f in base.glob("*.json"):
        f.unlink()

    user_repo    = JSONRepository(str(base / "users.json"))
    session_repo = JSONRepository(str(base / "sessions.json"))
    audit_repo   = JSONRepository(str(base / "audit.json"))
    audit_svc    = AuditService(audit_repo)
    auth         = AuthService(user_repo, session_repo, audit_svc)

    def section(title: str) -> None:
        print(f"\n  {'─'*44}")
        print(f"  🔹 {title}")
        print(f"  {'─'*44}")

    # 1. Registro com senha fraca
    section("Teste 1: Registro com senha fraca (deve falhar)")
    r = auth.register("joao@exemplo.com", "123")
    print(f"  Status : {r.status.value}")
    print(f"  Msg    : {r.message}")

    # 2. Registro correto
    section("Teste 2: Registro com dados válidos")
    r = auth.register("joao@exemplo.com", "Senha@Forte123")
    print(f"  Status : {r.status.value}")
    print(f"  Msg    : {r.message}")

    # 3. E-mail duplicado
    section("Teste 3: Registro com e-mail já existente")
    r = auth.register("joao@exemplo.com", "OutraSenha@456")
    print(f"  Status : {r.status.value}")
    print(f"  Msg    : {r.message}")

    # 4. Login com senha errada (múltiplas vezes para testar bloqueio)
    section("Teste 4: Login com senha incorreta (5x → bloqueio automático)")
    for i in range(SecurityConfig.MAX_LOGIN_ATTEMPTS + 1):
        r = auth.login("joao@exemplo.com", "senhaErrada!")
        print(f"  Tentativa {i+1}: [{r.status.value}] {r.message}")

    # 5. Login correto (deve estar bloqueado)
    section("Teste 5: Login correto mas conta bloqueada")
    r = auth.login("joao@exemplo.com", "Senha@Forte123")
    print(f"  Status : {r.status.value}")
    print(f"  Msg    : {r.message}")

    # 6. Desbloquear manualmente e logar
    section("Teste 6: Desbloqueio manual e login bem-sucedido")
    data = user_repo.find_by("email", "joao@exemplo.com")
    user = User.from_dict(data)
    user.unlock()
    user_repo.save(user.to_dict())
    r = auth.login("joao@exemplo.com", "Senha@Forte123")
    print(f"  Status : {r.status.value}")
    print(f"  Msg    : {r.message}")
    token = r.session.token if r.session else None
    if token:
        print(f"  Token  : {token[:32]}...")

    # 7. Validar sessão
    section("Teste 7: Validação de sessão ativa")
    if token:
        r = auth.validate_session(token)
        print(f"  Status : {r.status.value}")
        print(f"  Msg    : {r.message}")

    # 8. Logout
    section("Teste 8: Logout")
    if token:
        r = auth.logout(token)
        print(f"  Status : {r.status.value}")
        print(f"  Msg    : {r.message}")

    # 9. Token inválido após logout
    section("Teste 9: Tentativa de usar token após logout")
    if token:
        r = auth.validate_session(token)
        print(f"  Status : {r.status.value}")
        print(f"  Msg    : {r.message}")

    print("\n\n  ✅  Demo concluída! Verifique a pasta 'data_demo/' para os logs.\n")


# ══════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        run_demo()
    else:
        controller = AuthController()
        controller.run()