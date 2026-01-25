[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

# JSON Web Token (JWT) Library

A security-focused PHP 8.2+ library for creating, signing, encrypting, decrypting, and validating JSON Web Tokens (JWT). The package supports both JSON Web Signature (JWS) and JSON Web Encryption (JWE) flows with a pluggable algorithm registry and explicit key management.

## Why this library?
- Implements the core requirements of RFC 7515 (JWS), RFC 7516 (JWE), RFC 7518 (JWA), and RFC 7519 (JWT), with referenced formats from RFC 7517 (JWK).
- Clear separation between algorithm configuration, payload handling, token building/parsing, and validation.
- Defaults to safe behavior (claim validation, strict key handling) with escape hatches clearly marked as **testing-only**.

## Supported RFCs
- **RFC 7515:** JSON Web Signature (JWS)
- **RFC 7516:** JSON Web Encryption (JWE)
- **RFC 7517:** JSON Web Key (JWK) reference formats
- **RFC 7518:** JSON Web Algorithms (JWA)
- **RFC 7519:** JSON Web Token (JWT)
- **RFC 7638:** JSON Web Key (JWK) Thumbprint for `kid` derivation

## Installation
```bash
composer require phithi92/json-web-token
```

## Requirements
- PHP 8.2 or newer.
- The OpenSSL extension enabled (required for signing, encryption, and AES-GCM operations).
- Composer will install the `phpseclib/phpseclib` dependency automatically.


## Quick start
The typical flow is:

1. Configure algorithms and keys with `JwtKeyManager`.
2. Build a payload with `JwtPayload` (or provide an array of claims).
3. Create a token service via `JwtTokenServiceFactory`.
4. Create, serialize, and later decrypt/validate tokens via `JwtTokenService` (including claim-only validation or token-string reissuing when needed).
5. Apply additional business checks and optional JWT ID replay protection using `JwtValidator`.

### 1) Configure algorithms and keys
`JwtKeyManager` keeps the algorithm registry and an in-memory key/passphrase store. Keys must be provided in PEM format.
If you omit the `kid` when issuing tokens, the header factory derives one from the algorithm/enc (for example `RS256` or `RSA-OAEP-256/A256GCM`), so ensure your registered key IDs match or pass a `kid` explicitly.

```php
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;

$manager = new JwtKeyManager();

// For asymmetric algorithms (RS*, ES*, PS*, RSA-OAEP-256/A256GCM)
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

// Optional: add a passphrase for encrypted private keys
$manager->addPassphrase(
    passphrase: getenv('JWT_PRIVATE_KEY_PASSPHRASE'),
    kid: 'main-key'
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
    ->setJwtId('token-123')
    ->setNotBefore('+1 minute')
    ->setExpiration('+15 minutes')
    ->addClaim('role', 'admin');
```

### 3) Create and serialize a token
`JwtTokenService` orchestrates token building. Provide the algorithm identifier defined in `src/Config/algorithms.php`. Use `createTokenFromArray()` when you already have a claims array instead of a `JwtPayload` instance.

```php
use Phithi92\JsonWebToken\Token\Factory\JwtTokenServiceFactory;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$validator = new JwtValidator();
$service = JwtTokenServiceFactory::createDefault();

$bundle = $service->createToken(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);

$tokenString = $service->createTokenString(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);
```

If you already have a `JwtBundle`, you can serialize it into a compact token string:

```php
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;

$tokenString = JwtBundleCodec::serialize($bundle);
```

You can also create a token directly from an array of claims (useful when you already have decoded claims):

```php
$bundle = $service->createTokenFromArray(
    algorithm: 'RS256',
    manager: $manager,
    claims: [
        'iss' => 'https://issuer.example',
        'aud' => ['https://service.example'],
        'iat' => time(),
        'exp' => time() + 900,
        'role' => 'admin',
    ],
    validator: $validator,
    kid: 'main-key'
);
```


### 4) Decrypt and validate
Decrypts the compact string back into a `JwtBundle` while performing signature/encryption verification and claim checks. For workflows that only need to re-check claims without re-parsing headers, use `validateTokenClaims()`.

```php
$bundle = $service->decryptToken(
    token: $tokenString,
    manager: $manager,
    validator: $validator
);

$payload = $bundle->getPayload();
```

To run only structural checks (no claim validation), call `decryptTokenWithoutClaimValidation()`—this should be restricted to non-production tooling.

#### Claim-only validation
If you already trust the token structure but want to re-check claims (e.g., just before use), you can validate claims only:

```php
$isValid = $service->validateTokenClaims(
    token: $tokenString,
    manager: $manager,
    validator: $validator
);
```

### 5) Business validation
`JwtValidator` lets you enforce issuer, audience, and JWT ID expectations and verifies time-based claims. If you back JWT IDs with a registry (Redis/PDO), the service can automatically allow or deny IDs during issue/deny flows.

```php
$validator = new JwtValidator(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://service.example',
    expectedJwtId: 'token-123'
);

$validator->assertValidIssuer($payload);
$validator->assertValidAudience($payload);
$validator->assertValidJwtId($payload);
```

#### Validator configuration options
`JwtValidator` also supports clock skew, private claim expectations, and JWT ID allow/deny lists for replay protection.

```php
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$jwtIdValidator = new InMemoryJwtIdValidator(
    allowList: ['known-id-1', 'known-id-2'],
    denyList: ['revoked-id']
);

$validator = new JwtValidator(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://service.example',
    clockSkew: 30,
    expectedClaims: ['tenant' => 'acme', 'scope' => null],
    jwtIdValidator: $jwtIdValidator
);
```

You can back JWT ID validation with a persistent registry using Redis or PDO:

```php
use Phithi92\JsonWebToken\Token\Validator\PdoJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\RedisJwtIdValidator;

$pdoValidator = new PdoJwtIdValidator(
    pdo: new PDO('mysql:host=localhost;dbname=jwt', 'user', 'pass'),
    useAllowList: false
);

$redisValidator = new RedisJwtIdValidator(
    redis: $redis,
    useAllowList: true
);
```

If your validator implements `JwtIdRegistryInterface`, the token service can automatically deny replayed tokens:

```php
$service->denyBundle($bundle, $validator);
// or manually deny a specific ID for a TTL in seconds
$service->denyJwtId('token-123', 900, $validator);
```

### Refresh / reissue
`JwtTokenService::reissueBundle()` clones an existing bundle, strips time-based claims, and applies a new expiration window. Use `reissueBundleFromToken()` when you only have the compact token string.

```php
$newBundle = $service->reissueBundle(
    interval: '+30 minutes',
    bundle: $bundle,
    manager: $manager,
    validator: $validator
);
```

You can also reissue directly from the compact token string:

```php
$newBundle = $service->reissueBundleFromToken(
    token: $tokenString,
    interval: '+30 minutes',
    manager: $manager,
    validator: $validator
);
```

## Core classes
- **`JwtKeyManager`** — central registry for supported algorithms, key pairs, and passphrases. Throws if keys are missing or invalid.
- **`JwtPayload`** — mutable payload representation with helpers for standard claims and type enforcement. Raises dedicated exceptions for empty or malformed values.
- **`JwtTokenService`** — high-level entry point for building, serializing, decrypting, and reissuing tokens. Provides testing-only methods that bypass claim validation (`createTokenWithoutClaimValidation`, `decryptTokenWithoutClaimValidation`).
- **`JwtTokenServiceFactory`** — constructs a default service with issuer/reader/validator wiring.
- **`JwtTokenCreator` / `JwtTokenReader`** — focused helpers for issuance and decryption when you want to wire dependencies yourself.
- **`JwtValidator`** — reusable validator for issuer, audience, JWT ID, allow/deny list checks, and time-based constraints. `assert*` methods throw typed exceptions to help you differentiate failure causes.
- **`JwtBundle`** — aggregate of header, payload, signatures, and encryption artifacts returned by the factory/parsers.

## Supported algorithms
Algorithm identifiers map to handlers via `src/Config/algorithms.php`:

- **HMAC (JWS):** `HS256`, `HS384`, `HS512`
- **RSA PKCS#1 (JWS):** `RS256`, `RS384`, `RS512`
- **ECDSA (JWS):** `ES256`, `ES384`, `ES512`
- **RSA-PSS (JWS):** `PS256`, `PS384`, `PS512`
- **RSA-OAEP + AES-GCM (JWE):** `RSA-OAEP/A256GCM`, `RSA-OAEP-256/A256GCM`
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

## If this library helps you, consider supporting the project

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
