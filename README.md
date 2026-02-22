[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

# JSON Web Token (JWT) Library

**Security-first JWT implementation for PHP 8.2+.**  
Create, sign, encrypt, decrypt, validate, and reissue JSON Web Tokens with explicit key management and strict defaults.

Supports **JWS** and **JWE**, a pluggable algorithm registry, and fine-grained claim validation—without hiding security decisions behind magic defaults.

---

## Highlights

- ✅ RFC-compliant (JWS, JWE, JWA, JWT, JWK)
- 🔐 Secure-by-default claim validation and key handling
- 🧩 Clear separation of concerns (keys, payloads, algorithms, validation)
- 🔁 Built-in reissue / refresh workflows
- 🧪 Explicit *testing-only* escape hatches

---

## Interoperability

Tokens produced by this library are fully RFC-compliant and interoperable
with other JWT implementations across different languages and platforms.

No proprietary headers, claims, or encoding shortcuts are introduced.
As long as the same algorithms, keys, and claims are used, tokens can be
safely exchanged with other standards-compliant JWT stacks.

---

## Supported RFCs

- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7516** — JSON Web Encryption (JWE)
- **RFC 7517** — JSON Web Key (JWK, reference formats)
- **RFC 7518** — JSON Web Algorithms (JWA)
- **RFC 7519** — JSON Web Token (JWT)
- **RFC 7638** — JWK Thumbprints (`kid` derivation)

---

## Installation

```bash
composer require phithi92/json-web-token:^2.0
```

### Requirements

- PHP **8.2+**
- OpenSSL extension (required)
- `phpseclib/phpseclib` (installed automatically)

---

## Architecture Overview

```
JwtKeyManager        → keys, algorithms, passphrases
JwtPayload           → claims & type-safe helpers
JwtTokenService      → create / decrypt / reissue
JwtValidator         → issuer, audience, claims, replay protection
JwtBundle            → parsed token aggregate
```

Each component is usable independently, but the default factory wires everything safely for you.

---

## `JwtTokenService` Default Wiring (`createDefault()`)

`JwtTokenServiceFactory::createDefault()` is intentionally opinionated and builds a **consistent default dependency graph** so all operations share the same baseline behavior.

Internally, it creates:

- one shared `JwtValidator` instance (default: no expected issuer/audience, no clock skew, no private-claim expectations, no JTI registry)
- one `JwtPayloadCodec`
- one `JwtTokenIssuerFactory`
- one `JwtTokenDecryptorFactory`
- one `JwtTokenCreator` (with the shared default validator)
- one `JwtTokenReader`
- one `JwtClaimsValidationService` (with the shared default validator)
- one `JwtTokenReissuer` (with the shared default validator)

This means:

- Passing `null` as validator uses the shared default validator of this service instance.
- `createDefault()` returns a **fresh service graph per call** (instances are not reused globally).
- Claim validation is only as strict as your configured `JwtValidator`; for production you should usually pass an explicit validator with issuer/audience/JTI expectations.

> `createTokenWithoutClaimValidation()` and `decryptTokenWithoutClaimValidation()` are intentionally unsafe escape hatches for tests/tooling.

---

## Quick Start

### 1) Configure Keys & Algorithms

`JwtKeyManager` holds all keys in memory. **Asymmetric keys must be PEM-encoded.**
Symmetric secrets (HMAC, `dir`) live in the passphrase store.

```php
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;

$manager = new JwtKeyManager();

$manager->addKeyPair(
    private: file_get_contents('/path/private.pem'),
    public: file_get_contents('/path/public.pem'),
    kid: 'main-key'
);

$manager->addPassphrase(
    passphrase: getenv('JWT_KEY_PASSPHRASE'),
    kid: 'main-key'
);

// For symmetric algorithms (HS*, dir/A*GCM), register a shared secret
$manager->addPassphrase(
    passphrase: getenv('JWT_SHARED_SECRET'),
    kid: 'HS256'
);
```

> If no `kid` is provided when issuing tokens, one is derived from the JOSE header
> (e.g. `RS256`, `RSA-OAEP-256.A256GCM`). Make sure the corresponding key is registered
> under that `kid`, or pass a `kid` explicitly.

---

### 2) Build a Payload

`JwtPayload` provides helpers for standard claims and strict validation.

```php
use Phithi92\JsonWebToken\Token\JwtPayload;

$payload = (new JwtPayload())
    ->setIssuer('https://issuer.example')
    ->setAudience('https://service.example')
    ->setIssuedAt('now')
    ->setExpiration('+15 minutes')
    ->setJwtId('token-123')
    ->addClaim('role', 'admin');
```

Time-based helper setters such as `setIssuedAt()` and `setExpiration()` accept date/time strings, for example:

- `"now"`
- Relative strings (`+15 minutes`)
- Absolute datetime strings (`2026-01-01T00:00:00+00:00`)

> ℹ️ JWT `iat`, `nbf`, and `exp` are NumericDate values (seconds since Unix epoch in UTC).
> Always generate and compare timestamps in UTC to avoid timezone drift.

If you want to set UNIX timestamps directly, use `setClaimTimestamp()`:

```php
$payload
    ->setClaimTimestamp('iat', time())
    ->setClaimTimestamp('exp', time() + 900);
```

---

### 3) Create & Serialize a Token

```php
use Phithi92\JsonWebToken\Token\Factory\JwtTokenServiceFactory;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$service   = JwtTokenServiceFactory::createDefault();
$validator = new JwtValidator();

$token = $service->createTokenString(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);
```

You may also issue tokens directly from an array of claims:

```php
$bundle = $service->createTokenFromArray(
    algorithm: 'RS256',
    manager: $manager,
    claims: ['iss' => 'https://issuer.example', 'exp' => time() + 900],
    validator: $validator,
    kid: 'main-key'
);
```

---

### 4) Read (verify/decrypt) & Validate

```php
$bundle = $service->decryptToken(
    token: $token,
    manager: $manager,
    validator: $validator
);

$payload = $bundle->getPayload();
```

For JWS tokens this verifies the signature and reads the payload.
For JWE tokens this decrypts and then validates claims.

#### Claim-Only Validation

```php
$isValid = $service->validateTokenClaims(
    bundle: $bundle,
    validator: $validator
);
```

> ⚠️ `*WithoutClaimValidation()` methods exist **only** for tests or tooling.

---

## Error Handling Patterns

When issuing, parsing, decrypting, or validating tokens, prefer catching **specific exception types first** and only then falling back to a generic handler.

```php
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\UnsupportedTokenTypeException;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotYetValidException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuerException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidAudienceException;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureVerificationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Security\PassphraseNotFoundException;

try {
    $bundle = $service->decryptToken(
        token: $token,
        manager: $manager,
        validator: $validator
    );

    // Optional extra claim validation step
    $service->validateTokenClaims($bundle, $validator);

} catch (ExpiredPayloadException|NotYetValidException $e) {
    // 401: token is time-invalid (expired or not active yet)
} catch (InvalidIssuerException|InvalidAudienceException $e) {
    // 403: token is valid but not intended for this API/context
} catch (SignatureVerificationException|DecryptionException $e) {
    // 401: signature/JWE auth check failed
} catch (MalformedTokenException|InvalidTokenException|UnsupportedTokenTypeException $e) {
    // 400: structurally invalid or unsupported token
} catch (PassphraseNotFoundException $e) {
    // 500: server-side key configuration problem
}
```

### Recommended Mapping (API-friendly)

- **400 Bad Request**: malformed token, missing parts, unsupported format/type
- **401 Unauthorized**: invalid signature, failed decryption/auth tag, expired or not-yet-valid token
- **403 Forbidden**: issuer/audience/private-claim mismatch
- **500 Internal Server Error**: missing key material, passphrase, or other server misconfiguration

### Security Best Practices for Error Responses

- Return a **generic client message** (e.g. `"Invalid or expired token"`) to avoid leaking verification details.
- Log the exact exception message internally with request correlation IDs.
- Do not include secrets, raw token content, or key identifiers in public error payloads unless required.

---

### 5) Business Rules & Replay Protection

`JwtValidator` can enforce issuer, audience, private claims **and** protect against JWT replay attacks via a pluggable JWT ID registry.

### `jti` (JWT ID) Deep Dive

`jti` is the token identifier claim used to uniquely track a token and support replay prevention.

#### Validation behavior

- Without a `JwtIdValidatorInterface`, `jti` is optional and not checked.
- If a `JwtIdValidatorInterface` is configured, tokens **must** contain `jti`.
- The validator then checks whether the `jti` is allowed by the configured backend (in-memory, Redis, PDO).

#### Auto-generation behavior during issuing

When issuing via `JwtTokenService::createToken()` / `createTokenFromArray()` and the chosen validator has a JTI validator configured:

- if `jti` is missing, a new random `jti` is generated automatically
- this generated `jti` is pre-registered as allowed
- if `exp` is missing in that situation, issuing fails (because JTI tracking needs expiry context)

Practical recommendation:

- Set `jti` and `exp` explicitly for all tokens that should be replay-protected.
- Use `denyBundle()` after successful one-time use to invalidate the token ID for the remaining token lifetime.

#### InMemoryJwtIdValidator

`InMemoryJwtIdValidator` is a simple, deterministic implementation intended for tests, demos, and short‑lived processes.

```php
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$jwtIdValidator = new InMemoryJwtIdValidator(
    allowList: ['token-123'],
    denyList: ['revoked-token'],
    useAllowList: true
);

$validator = new JwtValidator(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://service.example',
    jwtIdValidator: $jwtIdValidator
);
```

##### How `useAllowList` works

- **`useAllowList = true`**  
  Only JWT IDs present in `allowList` are accepted.  
  Useful for **single‑use tokens**, login flows, or explicit grants.

- **`useAllowList = false` (default)**  
  All JWT IDs are accepted **unless** they appear in `denyList`.  
  Suitable for classic access tokens with revocation support.

When a token is successfully validated, the service can deny its JWT ID to prevent replay:

```php
$service->denyBundle($bundle, $validator);
```

> ⚠️ `InMemoryJwtIdValidator` is process‑local and non‑persistent.  
> Use Redis or PDO validators for production replay protection.

#### Storage backends for JTI replay protection

- `InMemoryJwtIdValidator`: ideal for tests and local demos; state is process-local.
- `RedisJwtIdValidator`: distributed runtime deny/allow lists with TTL support.
- `PdoJwtIdValidator`: relational persistence (requires `jwt_id_list` table with expiry column).

---

## Refresh / Reissue Tokens

```php
$newBundle = $service->reissueBundle(
    interval: '+30 minutes',
    bundle: $bundle,
    manager: $manager,
    validator: $validator
);
```

The original bundle remains untouched.

---

## Supported Algorithms

Identifiers map to handlers via `resources/algorithms.php`.

### JWS (signing)
- **HMAC:** `HS256` · `HS384` · `HS512`
- **RSA:** `RS256` · `RS384` · `RS512`
- **RSA-PSS:** `PS256` · `PS384` · `PS512`
- **ECDSA:** `ES256` · `ES384` · `ES512`

### JWE (encryption)
- **RSA-OAEP + AES-GCM:** `RSA-OAEP/A256GCM` · `RSA-OAEP-256/A256GCM`
- **Direct AES-GCM:** `A128GCM` · `A192GCM` · `A256GCM`

> Prefer **RSA-PSS** for new RSA signatures and **AES-GCM** for authenticated encryption. Pin algorithms per client.

---

## Security Best Practices

- 🔑 Never commit keys or passphrases
- 🔒 Always validate issuer & audience
- ⏱ Use short expiration windows
- 📌 Pin algorithms and `kid`s per client
- 🧯 Catch domain-specific exceptions only

---

## Development

```bash
composer install
composer run keys   # generate test keys
composer run test
composer run analyse
```

---

## License
Released under the MIT License. See [LICENSE](LICENSE).

## If this library helps you, consider supporting the project

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
