"""De onde vem a KEK de um cofre: senha digitada ou KEK já derivada (perfil das pastas)."""

from __future__ import annotations

from dataclasses import dataclass, field

from owl_vault.crypto.kdf import KdfPolicy, derive_kek
from owl_vault.domain.errors import AuthenticationError
from owl_vault.domain.models import KdfParams


@dataclass(frozen=True)
class KeySource:
    """Senha e/ou KEK pré-derivada (``kek = Argon2id(senha, salt, params)``).

    Cofres das pastas protegidas são criados com o salt/params do perfil; ao abri-los com o
    perfil destravado (PIN), a KEK já está em memória e o Argon2id não precisa rodar. Um cofre
    com outro salt exige a senha.
    """

    password: str | None = field(default=None, repr=False)
    salt: bytes | None = None
    params: KdfParams | None = None
    kek: bytes | None = field(default=None, repr=False)

    @staticmethod
    def of(value: str | KeySource) -> KeySource:
        return value if isinstance(value, KeySource) else KeySource(password=value)

    @property
    def has_kek(self) -> bool:
        return self.kek is not None and self.salt is not None and self.params is not None

    def kek_for(
        self, salt: bytes, params: KdfParams, policy: KdfPolicy, available_memory: int | None
    ) -> bytes:
        if self.kek is not None and salt == self.salt and params == self.params:
            return self.kek
        if self.password is None:
            raise AuthenticationError(
                "Este cofre foi protegido com outra senha mestra; digite a senha mestra dele."
            )
        return derive_kek(self.password, salt, params, policy, available_memory)
