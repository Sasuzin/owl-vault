"""Argon2id: política de limites, derivação da KEK e calibração (FORMAT §3, §10)."""

from __future__ import annotations

import os
import time
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from owl_vault.domain.errors import LimitError, ResourceError
from owl_vault.domain.limits import KEY_SIZE, MIB
from owl_vault.domain.models import KdfParams

KDF_ALGORITHM_ARGON2ID = 1
KDF_VERSION_13 = 0x13
SALT_SIZE = 32


@dataclass(frozen=True, slots=True)
class KdfPolicy:
    """Limites aceitos para parâmetros vindos de um cabeçalho (antes de autenticar)."""

    min_memory_kib: int
    max_memory_kib: int
    min_iterations: int
    max_iterations: int
    min_parallelism: int
    max_parallelism: int
    check_available_memory: bool


#: Política do build distribuído (UI e CLI). Igual à faixa que a criação pode produzir.
PRODUCTION_POLICY = KdfPolicy(
    min_memory_kib=64 * 1024,
    max_memory_kib=1024 * 1024,
    min_iterations=3,
    max_iterations=16,
    min_parallelism=1,
    max_parallelism=8,
    check_available_memory=True,
)

#: Política SOMENTE para testes automatizados (injetada explicitamente pelos testes).
TESTING_POLICY = KdfPolicy(
    min_memory_kib=8 * 1024,
    max_memory_kib=1024 * 1024,
    min_iterations=1,
    max_iterations=16,
    min_parallelism=1,
    max_parallelism=8,
    check_available_memory=False,
)

#: Parâmetros rápidos para testes (aceitos apenas por TESTING_POLICY).
TESTING_PARAMS = KdfParams(memory_kib=8 * 1024, iterations=1, parallelism=1)


def validate_params(params: KdfParams, policy: KdfPolicy) -> None:
    """Valida limites ANTES de qualquer alocação/derivação (proteção contra DoS)."""
    m, t, p = params.memory_kib, params.iterations, params.parallelism
    if not (policy.min_parallelism <= p <= policy.max_parallelism):
        raise LimitError("parâmetro de paralelismo do Argon2id fora dos limites")
    if not (policy.min_iterations <= t <= policy.max_iterations):
        raise LimitError("parâmetro de iterações do Argon2id fora dos limites")
    if not (policy.min_memory_kib <= m <= policy.max_memory_kib):
        raise LimitError("parâmetro de memória do Argon2id fora dos limites")
    if m < 8 * p:
        raise LimitError("parâmetros do Argon2id incoerentes (memória < 8 x paralelismo)")


def normalize_password(password: str) -> bytes:
    """Senha → bytes: Unicode NFC + UTF-8 (mesma senha em teclados/IMEs diferentes)."""
    if not isinstance(password, str):
        raise TypeError("senha deve ser str")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_kek(
    password: str,
    salt: bytes,
    params: KdfParams,
    policy: KdfPolicy,
    available_memory: int | None = None,
) -> bytes:
    """Deriva a KEK de 32 bytes com Argon2id. Não é cancelável.

    ``available_memory`` (bytes de memória comprometível disponível: RAM + arquivo de
    paginação) é fornecido pela camada de aplicação; com ``policy.check_available_memory``
    a derivação é recusada se faltar memória.
    """
    validate_params(params, policy)
    if len(salt) != SALT_SIZE:
        raise LimitError("salt do Argon2id com tamanho inválido")
    if policy.check_available_memory:
        avail = available_memory
        needed = params.memory_kib * 1024 + 256 * MIB
        if avail is not None and avail < needed:
            raise ResourceError(
                "memória livre insuficiente para derivar a chave deste cofre "
                f"(necessário ~{needed // MIB} MiB livres, disponível {avail // MIB} MiB). "
                "Feche outros programas e tente novamente."
            )
    pw = normalize_password(password)
    try:
        return bytes(
            hash_secret_raw(
                secret=pw,
                salt=salt,
                time_cost=params.iterations,
                memory_cost=params.memory_kib,
                parallelism=params.parallelism,
                hash_len=KEY_SIZE,
                type=Type.ID,
                version=KDF_VERSION_13,
            )
        )
    except MemoryError as exc:
        raise ResourceError("memória insuficiente para derivar a chave (Argon2id)") from exc


def calibrate(
    available_memory: int | None = None,
    total_physical_memory: int | None = None,
    target_seconds: float = 0.5,
    slow_seconds: float = 1.5,
    max_iterations: int = 16,
) -> KdfParams:
    """Escolhe parâmetros para ~``target_seconds`` nesta máquina (FORMAT §10).

    Prefere memória alta (até 512 MiB e no máximo 1/8 da RAM física, desde que haja
    memória comprometível livre) e depois aumenta ``t``.
    Nunca produz parâmetros abaixo de PRODUCTION_POLICY.
    """
    cpus = os.cpu_count() or 1
    parallelism = max(1, min(4, cpus))
    avail = available_memory
    candidates = [512 * 1024, 256 * 1024, 128 * 1024, 64 * 1024]
    if total_physical_memory is not None:
        candidates = [m for m in candidates if m * 1024 <= total_physical_memory // 8] or [
            64 * 1024
        ]
    if avail is not None:
        fitting = [m for m in candidates if avail >= m * 1024 + 512 * MIB]
        candidates = fitting or [64 * 1024]
    salt = os.urandom(SALT_SIZE)
    probe = b"owl-vault-calibration"

    def run(m: int, t: int) -> float:
        start = time.perf_counter()
        hash_secret_raw(probe, salt, t, m, parallelism, KEY_SIZE, Type.ID, KDF_VERSION_13)
        return time.perf_counter() - start

    chosen_m = candidates[-1]
    elapsed = 0.0
    for m in candidates:
        try:
            elapsed = run(m, 3)
        except MemoryError:
            continue
        chosen_m = m
        if elapsed <= slow_seconds:
            break
    iterations = 3
    if elapsed > 0:
        per_iter = elapsed / 3
        while iterations < max_iterations and per_iter * iterations < target_seconds:
            iterations += 1
    params = KdfParams(memory_kib=chosen_m, iterations=iterations, parallelism=parallelism)
    validate_params(params, PRODUCTION_POLICY)
    return params
