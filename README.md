[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

# JSON Web Token (JWT) Library

A security-focused PHP 8.2+ library for creating, signing, encrypting, decrypting, and validating JSON Web Tokens (JWT). The package supports both JSON Web Signature (JWS) and JSON Web Encryption (JWE) flows with a pluggable algorithm registry and explicit key management.

## Why this library?
- Implements the core requirements of RFC 7515 (JWS), RFC 7516 (JWE), and RFC 7519 (JWT).
- Clear separation between algorithm configuration, payload handling, token building/parsing, and validation.
- Defaults to safe behavior (claim validation, strict key handling) with escape hatches clearly marked as **testing-only**.

## Installation
```bash
composer require phithi92/json-web-token
```

## Quick start
The typical flow is:

1. Configure algorithms and keys with `JwtKeyManager`.
2. Build a payload with `JwtPayload`.
3. Create, serialize, and later decrypt/validate tokens via `JwtTokenFactory`.
4. Apply additional business checks using `JwtValidator`.

### 1) Configure algorithms and keys
`JwtKeyManager` keeps the algorithm registry and an in-memory key/passphrase store. Keys must be provided in PEM format.

```php
use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;

$manager = new JwtKeyManager();

// For asymmetric algorithms (RS*, ES*, PS*, RSA-OAEP-256_A256GCM)
$manager->addKeyPair(
    private: file_get_contents('/path/to/private.pem'),
    public: file_get_contents('/path/to/public.pem'),
    kid: 'main-key'
);

// For symmetric algorithms (HS*, A*GCM), register a single key
$manager->addPrivateKey(
    pemContent: file_get_contents('/path/to/hmac.key'),
    kid: 'hmac-key'
);
```

### 2) Build a payload
`JwtPayload` exposes helpers for standard claims and type-safe validation. Time-based claims accept `"now"`, relative expressions (e.g. `"+15 minutes"`), or UNIX timestamps.

```php
use Phithi92\JsonWebToken\Token\JwtPayload;

$payload = (new JwtPayload())
    ->setIssuer('https://issuer.example')
    ->setAudience(['https://service.example'])
    ->setIssuedAt('now')
    ->setNotBefore('+1 minute')
    ->setExpiration('+15 minutes')
    ->addClaim('role', 'admin');
```

### 3) Create and serialize a token
`JwtTokenFactory` orchestrates token building. Provide the algorithm identifier defined in `src/Config/algorithms.php`.

```php
use Phithi92\JsonWebToken\Token\Factory\JwtTokenFactory;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$validator = new JwtValidator();

$bundle = JwtTokenFactory::createToken(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);

$tokenString = JwtTokenFactory::createTokenString(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);
```

### 4) Decrypt and validate
Decrypts the compact string back into a `JwtBundle` while performing signature/encryption verification and claim checks.

```php
$bundle = JwtTokenFactory::decryptToken(
    token: $tokenString,
    manager: $manager,
    validator: $validator
);

$payload = $bundle->getPayload();
```

To run only structural checks (no claim validation), call `decryptTokenWithoutClaimValidation()`—this should be restricted to non-production tooling.

### 5) Business validation
`JwtValidator` lets you enforce issuer and audience expectations and verifies time-based claims.

```php
$validator->assertValidIssuer($payload, 'https://issuer.example');
$validator->assertValidAudience($payload, ['https://service.example']);
```

### Refresh / reissue
`JwtTokenFactory::reissueBundle()` clones an existing bundle, strips time-based claims, and applies a new expiration window.

```php
$newBundle = JwtTokenFactory::reissueBundle(
    interval: '+30 minutes',
    bundle: $bundle,
    manager: $manager,
    validator: $validator
);
```

## Core classes
- **`JwtKeyManager`** — central registry for supported algorithms, key pairs, and passphrases. Throws if keys are missing or invalid.
- **`JwtPayload`** — mutable payload representation with helpers for standard claims and type enforcement. Raises dedicated exceptions for empty or malformed values.
- **`JwtTokenFactory`** — high-level entry point for building, serializing, decrypting, and reissuing tokens. Provides testing-only methods that bypass claim validation (`createTokenWithoutClaimValidation`, `decryptTokenWithoutClaimValidation`).
- **`JwtValidator`** — reusable validator for issuer, audience, and time-based constraints. `assert*` methods throw typed exceptions to help you differentiate failure causes.
- **`JwtBundle`** — aggregate of header, payload, signatures, and encryption artifacts returned by the factory/parsers.

## Supported algorithms
Algorithm identifiers map to handlers via `src/Config/algorithms.php`:

- **HMAC (JWS):** `HS256`, `HS384`, `HS512`
- **RSA PKCS#1 (JWS):** `RS256`, `RS384`, `RS512`
- **ECDSA (JWS):** `ES256`, `ES384`, `ES512`
- **RSA-PSS (JWS):** `PS256`, `PS384`, `PS512`
- **RSA-OAEP + AES-GCM (JWE):** `RSA-OAEP-256_A128GCM`, `RSA-OAEP-256_A192GCM`, `RSA-OAEP-256_A256GCM`
- **Direct AES-GCM (JWE):** `A128GCM`, `A192GCM`, `A256GCM`

## Security checklist
- **Protect keys and passphrases.** Use environment variables or a secrets manager; never commit keys. `JwtKeyManager` keeps keys only in memory.
- **Always validate claims.** Use `JwtValidator` (default in factory methods) and explicitly check issuer/audience. Avoid the `*WithoutClaimValidation` methods outside tests.
- **Enforce HTTPS and short lifetimes.** Tokens should be transported only over TLS, with tight `nbf`/`exp` windows and frequent reissuing.
- **Pin algorithms and key IDs.** Store the expected algorithm and `kid` per client to block downgrade or key-mixup attacks.
- **Handle errors explicitly.** Catch the domain-specific exceptions (e.g., `TokenException`, `PayloadException`) to log and react safely without leaking sensitive details.

## Development
Install dependencies and generate local test keys:

```bash
composer install
composer run keys
```

Run quality checks:

```bash
composer run lint
composer run cs:check
composer run analyse
composer run test
```

Benchmark (optional):

```bash
composer run bench
```

## Troubleshooting tips
- **Invalid key or padding errors:** verify that the PEM file matches the chosen algorithm (e.g., RSA keys for `RS*`/`PS*`, EC keys for `ES*`).
- **Claim validation failures:** ensure `iat`, `nbf`, and `exp` are in sync with server time. Override the reference time by passing a `DateTimeImmutable` into `JwtPayload` for deterministic tests.
- **Audience/issuer mismatches:** the validator accepts single values or arrays; provide all allowed entries for multi-tenant systems.

## License
Released under the MIT License. See [LICENSE](LICENSE).

#If this library helps you, consider supporting the project

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
