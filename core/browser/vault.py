
from threading import RLock


class SecretVault:
    """In-memory vault for local secret values, addressed by reference."""

    def __init__(self, secrets=None):
        self._secrets = dict(secrets or {})
        self._lock = RLock()

        if not all(
            isinstance(name, str) and name
            for name in self._secrets
        ):
            raise ValueError("Secret references must be non-empty strings.")

        if not all(isinstance(value, str) for value in self._secrets.values()):
            raise ValueError("Secret values must be strings.")

    def names(self):
        """Return reference names only, never secret values."""
        with self._lock:
            return frozenset(self._secrets.keys())

    def has(self, secret_ref):
        with self._lock:
            return secret_ref in self._secrets

    def get(self, secret_ref):
        """Resolve a secret locally; never send this value to the LLM."""
        with self._lock:
            if secret_ref not in self._secrets:
                raise KeyError(f"Unknown secret reference: {secret_ref}")
            return self._secrets[secret_ref]

    def add(self, secret_ref, value):
        if not isinstance(secret_ref, str) or not secret_ref:
            raise ValueError("Secret reference must be a non-empty string.")
        if not isinstance(value, str):
            raise ValueError("Secret value must be a string.")

        with self._lock:
            self._secrets[secret_ref] = value

    def remove(self, secret_ref):
        with self._lock:
            if secret_ref not in self._secrets:
                return False
            del self._secrets[secret_ref]
            return True

    def clear(self):
        with self._lock:
            self._secrets.clear()
