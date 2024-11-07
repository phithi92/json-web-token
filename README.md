# Json-Web-Token

[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

The `JsonWebToken` PHP library enables seamless creation, signing, and validation of JSON Web Tokens (JWT) with support for JSON Web Signature (JWS) and JSON Web Encryption (JWE). Designed with a focus on security, it utilizes various cryptographic algorithms to ensure data integrity and confidentiality.

## Prerequisites

Before using this library, ensure your environment meets the following requirements:

- **PHP Version**: 8.2 or higher
- **PHP Extensions**: `openssl`
- **Composer**: For managing dependencies

## Overview

This library adheres to the standards in [**RFC 7519**](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), [**RFC 7515**](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), and [**RFC 7516**](https://datatracker.ietf.org/doc/html/rfc7516) (JWE). It uses HMAC algorithms like HS256 for **token signing** (JWS) and AES-based methods for **token encryption** (JWE), ensuring both data integrity and confidentiality.

More about JWT standards can be found in [**RFC 7519**](https://datatracker.ietf.org/doc/html/rfc7519).

## Security Considerations

When working with JWTs, consider the following best practices:

- **Store keys securely**: Ensure private keys are stored securely and are not hardcoded in your application code.
- **Use HTTPS**: Always transmit tokens over HTTPS to prevent interception.
- **Set expiration times**: Limit token lifespans by setting expiration times to reduce risk in case of token compromise.

## Installation

To integrate this library into your project, clone the repository or download the necessary files. It is recommended to use Composer for managing dependencies.

### Step 1: Clone the Repository

Clone the project to your local environment:

```bash
git clone https://github.com/phithi92/json-web-token.git
```

Or, install the library directly via Composer:

```bash
composer require phithi92/json-web-token
```

### Step 2: Install Dependencies

Ensure [Composer](https://getcomposer.org/) is installed, and then run:

```bash
composer update
```

The project uses the following dependencies (defined in `composer.json`):

**PHPUnit**: Used for unit testing to ensure robustness.

## Usage Guide

### Generate a Token

To create a JWT, set up the signing algorithm and payload, then generate the token.

```php
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;

$manager = new JwtAlgorithmManager(
    'RS256',        // Specify the algorithm
    null,           // Passphrase for symmetric algorithms (optional for asymmetric)
    'public-key',  // Private key for asymmetric algorithms
    'private-key'    // Public key for asymmetric algorithms
);

$payload = (new JwtPayload())
    ->setIssuer('https://myapp.com')
    ->setAudience('https://myapi.com')
    ->setNotBefore('+3 minutes')
    ->setExpiration('+15 minutes');

$token = JwtTokenFactory::createToken($manager, $payload);
```

### Validate a Token

To validate and decrypt a JWT, configure the algorithm manager and retrieve the payload.

```php
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtTokenFactory;

$manager = new JwtAlgorithmManager(
    'RS256',        // Specify the algorithm
    null,           // Passphrase for symmetric algorithms (optional for asymmetric)
    'public-key',  // Private key for asymmetric algorithms
    'private-key'    // Public key for asymmetric algorithms
);

$token = JwtTokenFactory::decryptToken($manager,$encodedToken);
$payload = $token->getPayload();
```

### Refresh Token

Refresh an existing JWT by extending its expiration.

```php
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtTokenFactory;

$manager = new JwtAlgorithmManager(
    'RS256',        // Specify the algorithm
    null,           // Passphrase for symmetric algorithms (optional for asymmetric)
    'public-key',  // Private key for asymmetric algorithms
    'private-key'    // Public key for asymmetric algorithms
);

$token = JwtTokenFactory::refreshToken($manager,$encodedToken,'+15 minutes');
```

### Error Handling

Handle exceptions for robust error management in your application:

```php
use Phithi92\JsonWebToken\Exception\Json\JsonException;
use Phithi92\JsonWebToken\Exception\Token\TokenException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

try {
    // ...   
} catch (JsonException $e) {
    // JSON errors during JWT processing
} catch (PayloadException $e) {
    // Errors with the JWT payload
} catch (AlgorithmException $e) {
    // Issues with the signing algorithm
} catch (TokenException $e) {
    // General token error
}
```

## Supported Algorithms

The `JsonWebToken` class supports a variety of cryptographic algorithms for both JSON Web Signature (JWS) and JSON Web Encryption (JWE). Below are the lists of supported algorithms:

**JSON Web Signature (JWS) Algorithmen:**

`HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`

**JSON Web Encryption (JWE) Algorithmen:**

`RSA-OAEP`, `RSA-OAEP+A192GCM`, `RSA-OAEP+A256GCM`, `RSA1_5`, `A128GCM`, `A192GCM`, `A256GCM`

## Running Tests and Benchmarks

This project includes both unit tests and benchmarks to ensure reliability and performance.

### Unit Tests

Unit tests are included to verify the functionality of the library. These tests cover token creation, validation, and error handling. To run the unit tests, use the following command:

```bash
composer test
```

All PHPUnit test cases are located in the tests/phpunit directory and ensure that the library functions correctly across various scenarios.

### Benchmarks

Benchmarks are included to measure the performance of different algorithms and operations within the library. To run the benchmarks, use the following command:

```bash
composer benchmark
```

#### Results

**System Specifications**

The benchmarks were conducted on the following system:

- **Device**: MacBook Air (2020)
- **Processor**: Apple M1 Chip (8-Core CPU)
- **RAM**: 16 GB
- **Operating System**: macOS Sequoia (Version 15.x)
- 

| subject  | memory  | min       | max      | mode      | rstdev | stdev   |
| -------- | ------- | --------- | -------- | --------- | ------ | ------- |
| HS256    | 1.747mb | 41.203μs  | 42.662μs | 41.403μs  | ±1.38% | 0.575μs |
| HS384    | 1.747mb | 41.615μs  | 42.633μs | 42.213μs  | ±0.88% | 0.371μs |
| HS512    | 1.747mb | 41.868μs  | 42.680μs | 42.523μs  | ±0.74% | 0.312μs |
| RS256    | 1.747mb | 992.166μs | 1.010ms  | 1.001ms   | ±0.58% | 5.820μs |
| RS384    | 1.747mb | 996.938μs | 1.010ms  | 1.009ms   | ±0.53% | 5.355μs |
| RS512    | 1.747mb | 990.179μs | 1.005ms  | 1.003ms   | ±0.55% | 5.504μs |
| ES256    | 1.747mb | 988.590μs | 1.005ms  | 998.615μs | ±0.61% | 6.054μs |
| ES384    | 1.747mb | 992.057μs | 1.009ms  | 1.004ms   | ±0.64% | 6.401μs |
| ES512    | 1.747mb | 990.365μs | 1.010ms  | 1.009ms   | ±0.76% | 7.672μs |
| PS256    | 1.747mb | 991.279μs | 1.010ms  | 994.852μs | ±0.81% | 8.109μs |
| PS384    | 1.747mb | 992.116μs | 1.015ms  | 995.140μs | ±0.94% | 9.390μs |
| PS512    | 1.747mb | 989.058μs | 1.009ms  | 997.819μs | ±0.67% | 6.738μs |
| RSA-OAEP | 1.747mb | 1.551ms   | 1.572ms  | 1.557ms   | ±0.53% | 8.275μs |
| A128GCM  | 1.747mb | 80.575μs  | 82.702μs | 81.990μs  | ±0.87% | 0.708μs |
| A192GCM  | 1.747mb | 80.537μs  | 81.802μs | 80.735μs  | ±0.65% | 0.530μs |
| A256GCM  | 1.747mb | 80.365μs  | 82.659μs | 82.102μs  | ±0.96% | 0.786μs |

## Support

Donations are a great way to support creators and their work. Every contribution helps sustain projects and shows appreciation for their efforts, making a real difference.

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
