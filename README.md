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
composer require phithi92/json-web-token
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

> If no `kid` is provided when issuing tokens, one is derived from the header algorithm
> (e.g. `RS256`, `RSA-OAEP-256/A256GCM`). Make sure the corresponding key is registered
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

Time-based claims accept:
- `"now"`
- Relative strings (`+15 minutes`)
- UNIX timestamps

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

### 4) Decrypt & Validate

```php
$bundle = $service->decryptToken(
    token: $token,
    manager: $manager,
    validator: $validator
);

$payload = $bundle->getPayload();
```

#### Claim-Only Validation

```php
$isValid = $service->validateTokenClaims(
    bundle: $bundle,
    validator: $validator
);
```

> ⚠️ `*WithoutClaimValidation()` methods exist **only** for tests or tooling.

---

### 5) Business Rules & Replay Protection

`JwtValidator` can enforce issuer, audience, private claims **and** protect against JWT replay attacks via a pluggable JWT ID registry.

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
