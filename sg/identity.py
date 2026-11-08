"""Ed25519-signed capability tokens (PyJWT EdDSA, recipe from scout SC2).

Reused: PyJWT[crypto] (already in .venv). We only add revocation + per-jti budget,
which JWT libraries do not track.
"""
from __future__ import annotations

from collections import Counter

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sg.schema import TokenClaims


class TokenError(PermissionError):
    pass


class Identity:
    """One keypair per Gateway. Agents never see the private key."""

    def __init__(self) -> None:
        self._sk = Ed25519PrivateKey.generate()
        self.pk = self._sk.public_key()
        self.revoked: set[str] = set()
        self.calls: Counter[str] = Counter()  # jti -> calls spent

    def mint(self, claims: TokenClaims) -> str:
        return jwt.encode(claims.model_dump(mode="json"), self._sk, algorithm="EdDSA")

    def verify(self, token: str) -> TokenClaims:
        """Raises TokenError on bad signature / expired / revoked / garbage."""
        try:
            raw = jwt.decode(token, self.pk, algorithms=["EdDSA"], options={"require": ["exp", "jti"]})
        except jwt.PyJWTError as e:
            raise TokenError(f"invalid token: {type(e).__name__}: {e}") from None
        claims = TokenClaims.model_validate(raw)
        if claims.jti in self.revoked:
            raise TokenError(f"invalid token: revoked jti {claims.jti}")
        return claims

    def revoke(self, jti: str) -> None:
        self.revoked.add(jti)

    def spend(self, jti: str) -> int:
        """Count one call against this token; returns calls spent so far."""
        self.calls[jti] += 1
        return self.calls[jti]
