"""Field-level encryption at rest (Fernet / AES-128-CBC + HMAC-SHA256).

Sensitive columns (mobile number, CTC, stipend, MFA secret) use the EncText /
EncFloat column types, so the SQLite file never contains them in plaintext.
MultiFernet lets you rotate keys: put the NEW key first in FIELD_KEYS, keep the
old one after it, then run `flask rotate-keys`.
"""
from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy.types import Text, TypeDecorator

_fernet = None


def init(keys):
    global _fernet
    if isinstance(keys, str):
        keys = [k.strip() for k in keys.split(",") if k.strip()]
    _fernet = MultiFernet([Fernet(k.encode() if isinstance(k, str) else k) for k in keys])


def encrypt(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def rotate(token: str) -> str:
    return _fernet.rotate(token.encode()).decode()


class EncText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt(str(value))

    def process_result_value(self, value, dialect):
        return None if value is None else decrypt(value)


class EncFloat(EncText):
    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt(repr(float(value)))

    def process_result_value(self, value, dialect):
        return None if value is None else float(decrypt(value))
