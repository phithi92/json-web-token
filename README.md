[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

# JSON Web Token (JWT) Library

**Security-first JWT implementation for PHP 8.2+.**
Create, sign, encrypt, decrypt, validate, and reissue JSON Web Tokens with explicit key management and strict defaults.

The library supports both **JWS** and **JWE**, uses a pluggable algorithm registry, and keeps security decisions visible instead of hiding them behind magic defaults.

---

## What this library gives you

- ✅ RFC-compliant JWT, JWS, JWE, JWA, and JWK-related workflows
- 🔐 Explicit key, passphrase, algorithm, and `kid` handling
- 🧩 Separate building blocks for keys, payloads, token processing, and claim validation
- 🔁 Built-in reissue / refresh support
- 🧪 Clearly marked unsafe methods for testing and tooling only

---

## Installation

```bash
composer require phithi92/json-web-token:^2.0
```

### Requirements

- PHP **8.2+**
- OpenSSL extension
- `phpseclib/phpseclib` (installed automatically)

---

## Interoperability

Tokens produced by this library are standards-compliant and can be exchanged with other JWT libraries as long as the same algorithms, keys, and claims are used.

The library does not introduce proprietary headers, custom encodings, or non-standard token formats.

---

## Supported RFCs

- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7516** — JSON Web Encryption (JWE)
- **RFC 7517** — JSON Web Key (JWK, reference formats)
- **RFC 7518** — JSON Web Algorithms (JWA)
- **RFC 7519** — JSON Web Token (JWT)
- **RFC 7638** — JWK Thumbprints (`kid` derivation)

---

## How the library is structured

### Main components

```text
JwtKeyManager        → keys, passphrases, algorithm metadata, kid resolution
JwtPayload           → claims and type-safe helpers
JwtValidator         → issuer, audience, time, private claims, replay protection
JwtTokenService      → issue, serialize, read, decrypt, validate, reissue
JwtBundle            → parsed token aggregate (header + payload + crypto parts)
```

### Mental model

A typical workflow looks like this:

1. Register key material in `JwtKeyManager`.
2. Build claims with `JwtPayload` or pass an array.
3. Define validation rules with `JwtValidator`.
4. Create or read tokens through `JwtTokenService`.
5. Optionally deny a `jti` after use to prevent replay.

If you only want one entry point, use `JwtTokenServiceFactory::createDefault()`.

---

## Default service wiring

`JwtTokenServiceFactory::createDefault()` builds a fresh, opinionated service graph for one library instance.

It creates:

- one shared `JwtValidator` instance
  - defaults: no expected issuer, no expected audience, no clock skew,
    no private-claim expectations, no JTI registry
- one `JwtPayloadCodec`
- one `JwtTokenIssuerFactory`
- one `JwtTokenDecryptorFactory`
- one `JwtTokenCreator`
- one `JwtTokenReader`
- one `JwtClaimsValidationService`
- one `JwtTokenReissuer`

Important behavior:

- Passing `null` as validator uses the shared default validator from that service instance.
- Each `createDefault()` call returns a **new** dependency graph.
- Production code should usually provide an explicit `JwtValidator` with issuer, audience, and optional JTI requirements.

> `createTokenWithoutClaimValidation()` and `decryptTokenWithoutClaimValidation()` are intentionally unsafe escape hatches for tests and tooling.

---

## Quick start

### 1) Register keys and secrets

`JwtKeyManager` stores all key material in memory.

- **Asymmetric keys** must be PEM-encoded.
- **Symmetric secrets** (for HMAC or direct encryption) are stored as passphrases.

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

// For symmetric algorithms such as HS256 or direct AES-GCM
$manager->addPassphrase(
    passphrase: getenv('JWT_SHARED_SECRET'),
    kid: 'HS256'
);
```

### 2) Build the payload

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

Time helper methods such as `setIssuedAt()` and `setExpiration()` accept:

- `'now'`
- relative strings such as `'+15 minutes'`
- absolute values such as `'2026-01-01T00:00:00+00:00'`

JWT time claims (`iat`, `nbf`, `exp`) are NumericDate values, so generate and compare them in UTC.

If you already have timestamps, set them directly:

```php
$payload
    ->setClaimTimestamp('iat', time())
    ->setClaimTimestamp('exp', time() + 900);
```

### 3) Define validation rules

```php
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

$validator = new JwtValidator(
    expectedIssuer: 'https://issuer.example',
    expectedAudience: 'https://service.example',
    clockSkew: 0,
    expectedClaims: ['role' => 'admin']
);
```

### 4) Create a token

```php
use Phithi92\JsonWebToken\Token\Factory\JwtTokenServiceFactory;

$service = JwtTokenServiceFactory::createDefault();

$token = $service->createTokenString(
    algorithm: 'RS256',
    manager: $manager,
    payload: $payload,
    validator: $validator,
    kid: 'main-key'
);
```

You can also create tokens from a plain claims array:

```php
$bundle = $service->createTokenFromArray(
    algorithm: 'RS256',
    manager: $manager,
    claims: [
        'iss' => 'https://issuer.example',
        'aud' => 'https://service.example',
        'exp' => time() + 900,
    ],
    validator: $validator,
    kid: 'main-key'
);
```

If you want the compact string directly from an array, use `createTokenStringFromArray()`.

### 5) Read, verify, or decrypt a token

```php
$bundle = $service->decryptToken(
    token: $token,
    manager: $manager,
    validator: $validator
);

$payload = $bundle->getPayload();
```

Behavior depends on the token type:

- For **JWS**, the library verifies the signature and returns the parsed bundle.
- For **JWE**, the library decrypts the token and then validates the claims.

### 6) Validate claims separately

```php
$isValid = $service->validateTokenClaims(
    bundle: $bundle,
    validator: $validator
);
```

> Methods ending in `WithoutClaimValidation()` exist only for tests or tooling.

### 7) Reissue a token

```php
$newBundle = $service->reissueBundle(
    interval: '+30 minutes',
    bundle: $bundle,
    manager: $manager,
    validator: $validator
);
```

The original bundle stays unchanged.

---

## Choosing algorithms and `kid`s

The algorithm controls which key material must exist in `JwtKeyManager`.

### JWS algorithms

- **HMAC:** `HS256`, `HS384`, `HS512`
- **RSA:** `RS256`, `RS384`, `RS512`
- **RSA-PSS:** `PS256`, `PS384`, `PS512`
- **ECDSA:** `ES256`, `ES384`, `ES512`

### JWE algorithms

- **RSA-OAEP + AES-GCM:** `RSA-OAEP/A256GCM`, `RSA-OAEP-256/A256GCM`
- **Direct AES-GCM:** `A128GCM`, `A192GCM`, `A256GCM`

The identifiers map to handlers via `resources/algorithms.php`.

### `kid` resolution rules

If you do not pass a `kid` while issuing, the library derives one from the JOSE header, for example:

- `RS256`
- `RSA-OAEP-256.A256GCM`

Make sure the required key or passphrase was registered under that identifier, or pass a `kid` explicitly.

Recommendation: pin both the algorithm and the `kid` per client or integration.

> Prefer **RSA-PSS** for new RSA signatures and **AES-GCM** for authenticated encryption.

---

## Claim validation and replay protection

`JwtValidator` can enforce:

- issuer (`iss`)
- audience (`aud`)
- time-based claims (`exp`, `nbf`, `iat`)
- private claims
- JWT ID (`jti`) checks through a pluggable registry

### `jti` behavior

`jti` is the token identifier claim used for replay protection.

#### Validation behavior

- Without a `JwtIdValidatorInterface`, `jti` is optional and not checked.
- If a `JwtIdValidatorInterface` is configured, tokens **must** contain `jti`.
- The configured backend decides whether that `jti` is allowed.

#### Issuing behavior

When issuing with `createToken()` or `createTokenFromArray()` and the chosen validator has a JTI validator configured:

- a missing `jti` is generated automatically
- the generated `jti` is pre-registered as allowed
- issuing fails if `exp` is missing, because replay tracking needs expiry context

Practical recommendation:

- Set `jti` and `exp` explicitly for replay-protected tokens.
- Call `denyBundle()` after successful one-time use.

### In-memory example

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

#### How `useAllowList` works

- **`useAllowList = true`**<br>Only JWT IDs in `allowList` are accepted.<br>Good for single-use flows or explicit grants.

- **`useAllowList = false`**<br>All JWT IDs are accepted unless they appear in `denyList`.<br>Good for classic access tokens with revocation support.

After successful validation you can deny the bundle's `jti`:

```php
$service->denyBundle($bundle, $validator);
```

> `InMemoryJwtIdValidator` is process-local and not persistent. Use Redis or PDO-based validators for production replay protection.

### Available JTI backends

- `InMemoryJwtIdValidator`: good for tests and local demos
- `RedisJwtIdValidator`: distributed allow/deny lists with TTL support
- `PdoJwtIdValidator`: relational persistence (`jwt_id_list` table with an expiry column)

---

## Error handling

Catch specific exception types first and fall back to a generic handler only at the boundary of your application.

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

    $service->validateTokenClaims($bundle, $validator);
} catch (ExpiredPayloadException | NotYetValidException $e) {
    // 401: token is time-invalid
} catch (InvalidIssuerException | InvalidAudienceException $e) {
    // 403: token is valid but not intended for this API/context
} catch (SignatureVerificationException | DecryptionException $e) {
    // 401: signature or JWE auth check failed
} catch (MalformedTokenException | InvalidTokenException | UnsupportedTokenTypeException $e) {
    // 400: structurally invalid or unsupported token
} catch (PassphraseNotFoundException $e) {
    // 500: server-side key configuration problem
}
```

### Recommended HTTP mapping

- **400 Bad Request**: malformed token, missing parts, unsupported type or format
- **401 Unauthorized**: invalid signature, failed decryption, expired token, not-yet-valid token
- **403 Forbidden**: issuer, audience, or private-claim mismatch
- **500 Internal Server Error**: missing keys, passphrases, or other server misconfiguration

### Error response best practices

- Return a generic client-facing message such as `Invalid or expired token`.
- Log the precise exception internally.
- Avoid exposing secrets, raw token content, or sensitive key details in public responses.

---

## Security checklist

- 🔑 Never commit keys or passphrases
- 🔒 Always validate issuer and audience in production
- ⏱ Use short expiration windows
- 📌 Pin algorithms and `kid`s per client
- 🧯 Catch domain-specific exceptions only
- 🧪 Treat `*WithoutClaimValidation()` methods as test-only APIs

---

## Development

```bash
composer install
composer run keys
composer run test
composer run analyse
```

---

## License

Released under the MIT License. See [LICENSE](LICENSE).

## Support the project

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
