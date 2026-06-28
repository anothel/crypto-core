# Key Lifecycle

Current `crypto-core` key containers are in-memory primitives:

- `SecretKey`
- `PublicKey`
- `PrivateKey`
- `KeyPair`
- `KeyStore`

They do not implement production KMS, HSM, Secret Manager, tenant scoping,
rotation, or audit logging.

## KeyProvider Boundary

Production integrations should use KMS, HSM, or Secret Manager outside the
current in-memory `KeyStore`. A future provider-backed key boundary should
resolve keys by purpose and scope instead of passing raw key material through
application code.

Required metadata for managed keys:

- `keyId`
- `purpose`
- `tenant` or `scope`
- `createdAt`
- `activatedAt`
- `deactivatedAt`
- `destroyedAt`
- `algorithmSuite`
- `owner`
- `rotationPolicy`
- `compromiseStatus`

## Lifecycle Procedures

Before production use, operating teams need runbooks for:

- key generation
- key distribution
- key activation and deactivation
- key rotation
- key destruction
- suspected key compromise
- decrypt-failure incidents
- backup and recovery
- administrator approval and separation of duties

## Current Safety Boundaries

- `SecureBuffer` zeroes owned bytes on destruction.
- `PrivateKey`, `SecretKey`, and `KeyPair` are move-only where ownership
  matters.
- Secret-owning public types are not stream-insertable.
- Raw key export remains possible for APIs that explicitly expose it; callers
  must treat exported material as secret.
