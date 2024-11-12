# Json-Web-Token

[![PHP Version](https://img.shields.io/packagist/php-v/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token) [![Latest Version](https://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) [![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge)](https://github.com/phithi92/json-web-token/actions) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

The `JsonWebToken` PHP library enables seamless creation, signing, and validation of JSON Web Tokens (JWT) with support for JSON Web Signature (JWS) and JSON Web Encryption (JWE). Designed with a focus on security, it utilizes various cryptographic algorithms to ensure data integrity and confidentiality.

---

## Table of Contents

- [Overview](#overview)
- [Security Considerations](#security-considerations)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
  - [Generate a Token](#generate-a-token)
  - [Validate a Token](#validate-a-token)
  - [Refresh a Token](#refresh-a-token)
  - [Error Handling](#error-handling)
- [Supported Algorithms](#supported-algorithms)
- [Running Tests and Benchmarks](#running-tests-and-benchmarks)
  - [PHPUnit Tests](#phpunit-tests)
  - [PHPBench Tests](#phpbench-tests)
- [Benchmark](#benchmark)
- [Support](#support)

---

## Overview

This library adheres to the standards in [**RFC 7519**](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), [**RFC 7515**](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), and [**RFC 7516**](https://datatracker.ietf.org/doc/html/rfc7516) (JWE). It uses HMAC algorithms like HS256 for **token signing** (JWS) and AES-based methods for **token encryption** (JWE), ensuring both data integrity and confidentiality.

---

## Security Considerations

When working with JWTs, consider the following best practices:

- **Store keys securely**: Ensure private keys are stored securely and are not hardcoded in your application code.
- **Use HTTPS**: Always transmit tokens over HTTPS to prevent interception.
- **Set expiration times**: Limit token lifespans by setting expiration times to reduce risk in case of token compromise.

---

## Prerequisites

Before using this library, ensure your environment meets the following requirements:

- **PHP Version**: 8.2 or higher
- **PHP Extensions**: `openssl`
- **Composer**: For managing dependencies

---

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
**PHPBench**: Used for benchmark to ensure efficiency.

---

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

### Refresh a Token

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

### Validate a Token

To validate and decrypt a JWT, configure the algorithm manager and retrieve the payload.  
**Note:** This validation covers only time-based claims (such as `exp`, `nbf`, and `iat`).  
Validation of `audience` and `issuer` claims can be performed manually if required.

```php
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtTokenFactory;

$manager = new JwtAlgorithmManager(
    'RS256',        // Specify the algorithm
    null,           // Passphrase for symmetric algorithms (optional for asymmetric)
    'public-key',   // Private key for asymmetric algorithms
    'private-key'   // Public key for asymmetric algorithms
);

$token = JwtTokenFactory::decryptToken($manager, $encodedToken);
$payload = $token->getPayload();
```

### Validate Payload

**Validate Issuer**

```php
$token->getPayload()->validateIssuer($issuer);
```

**Validate Audience**

```php
$token->getPayload()->validateAudience($audience);
```

### Error Handling

Handle exceptions for robust error management in your application:

```php
use Phithi92\JsonWebToken\Exception\Json\JsonException;
use Phithi92\JsonWebToken\Exception\Token\TokenException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Cryptography\CryptographyException;

try {
    // ...   
} catch (JsonException $e) {
    // JSON errors during JWT processing
} catch (PayloadException $e) {
    // Errors with the JWT payload
} catch (CryptographyException $e) {
    // Issues with the signing algorithm
} catch (TokenException $e) {
    // General token error
}
```

---

## Supported Algorithms

The `JsonWebToken` class supports a variety of cryptographic algorithms for both JSON Web Signature (JWS) and JSON Web Encryption (JWE). Below are the lists of supported algorithms:

**JSON Web Signature (JWS) Algorithmen:**

`HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`

**JSON Web Encryption (JWE) Algorithmen:**

`RSA-OAEP`, `RSA-OAEP+A192GCM`, `RSA-OAEP+A256GCM`, `RSA1_5`, `A128GCM`, `A192GCM`, `A256GCM`

---

## Running Tests and Benchmarks

This project includes both unit tests and benchmarks to ensure reliability and performance.

### PHPUnit Tests

Unit tests are included to verify the functionality of the library. These tests cover token creation, validation, and error handling. To run the unit tests, use the following command:

```bash
composer test
```

All PHPUnit test cases are located in the tests/phpunit directory and ensure that the library functions correctly across various scenarios.

### PHPBench Tests

Benchmarks are included to measure the performance of different algorithms and operations within the library. To run the benchmarks, use the following command:

```bash
composer benchmark
```

---

## Benchmarking

This project uses automated benchmarks that run with each new commit or pull request via GitHub Actions. You can view the benchmark results in the **GitHub Actions Workflow**.

### How to Find the Results

1. Go to the **Actions** tab in this repository.
2. Select the latest **Benchmark Workflow** run.
3. Here, you’ll find detailed results for the current benchmarks.

> Note: Benchmarks are updated automatically, so the latest results are always available in the most recent workflow run.

---

## Support

Donations are a great way to support creators and their work. Every contribution helps sustain projects and shows appreciation for their efforts, making a real difference.

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
