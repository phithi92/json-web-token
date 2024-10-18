⚠️ **Attention:** This project is still in **active development**. Unexpected changes and errors may occur. ⚠️

---

# JsonWebToken PHP Library

[![Latest Version](http://img.shields.io/packagist/v/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/releases) [![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge)](LICENSE) [![Issues](https://img.shields.io/github/issues/phithi92/json-web-token.svg?style=for-the-badge)](https://github.com/phithi92/json-web-token/issues) ![Build](https://img.shields.io/github/actions/workflow/status/phithi92/json-web-token/php.yml?branch=main&style=for-the-badge) [![Total Downloads](https://img.shields.io/packagist/dt/phithi92/json-web-token.svg?style=for-the-badge)](https://packagist.org/packages/phithi92/json-web-token)

The `JsonWebToken` class is a PHP library that facilitates the creation, signing, and validation of JSON Web Tokens (JWT), supporting both JSON Web Signature (JWS) and JSON Web Encryption (JWE). It provides a secure framework for generating tokens using various cryptographic algorithms to ensure data integrity and confidentiality.

## Prerequisites

Before using this library, ensure your environment meets the following requirements:

- **PHP Version**: 8.1 or higher
- **PHP Extensions**: `openssl`
- **Composer**: For managing dependencies

## How the Library Works

This library operates according to key standards such as [**RFC 7519**](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), [**RFC 7515**](https://datatracker.ietf.org/doc/html/rfc7515) (JWS), and [**RFC 7516**](https://datatracker.ietf.org/doc/html/rfc7516) (JWE). During **token signing** (JWS), the library uses the HMAC algorithm (e.g., HS256) to create a signature by combining the token's header and payload with a secret key. This signature ensures the token's integrity, following the specifications in [**RFC 7515**](https://datatracker.ietf.org/doc/html/rfc7515).

For **token encryption** (JWE), the payload is encrypted using algorithms like AES, as defined in [**RFC 7516**](https://datatracker.ietf.org/doc/html/rfc7516), ensuring that only authorized recipients can decrypt and access the token's data. The entire process relies on **Base64URL encoding** ([**RFC 4648**](https://datatracker.ietf.org/doc/html/rfc4648)) to safely transmit the token over the web.

You can find more information about the JWT RFC [here](https://datatracker.ietf.org/doc/html/rfc7519).

## Installation

To integrate this library into your project, clone the repository or download the necessary files. It is recommended to use Composer for managing dependencies.

### Step 1: Clone the Repository

Clone the project to your local environment:

```bash
git clone https://github.com/phithi92/json-web-token.git
```

or

You can install the library directly through Composer by running:

```bash
composer require phithi92/json-web-token
```

### Step 2: Install Dependencies

Ensure [Composer](https://getcomposer.org/) is installed, and run the following command to install the required dependencies:

```bash
composer install
```

The project uses the following dependencies (defined in `composer.json`):

- **PHPUnit**: Used for unit testing to ensure robustness.

## Usage Guide

#### Generating a JSON Web Token (JWT)

To generate a JWT, instantiate the `JsonWebToken` class and call the `create()` method. This method can generate either a signed (JWS) or encrypted (JWE) token.

```php
use Phithi92\JsonWebToken\JsonWebToken;
use Phithi92\JsonWebToken\PayloadBuilder;
use Phithi92\JsonWebToken\Security\Openssl;
```

For RSA Algorithm

```php
$payload = (new PayloadBuilder())
    ->setExpiration('+15min')
    ->setIssuer('issuer')
    ->setAudience('audience')
    ->addField('your-field', 'your-data');

$openssl = (new Openssl())
    ->setPrivateKey('your-private-key')
    ->setPublicKey('your-public-key');

$jwt = new JsonWebToken($openssl);
$jwtToken = $jwt->create($payload, '', 'JWE', 'RSA-OAEP+A128KW');
```

For Hmac Algorithm

```php
$payload = (new PayloadBuilder())
    ->setExpiration('+15min')
    ->setIssuer('issuer')
    ->setAudience('audience')
    ->addField('custom', 'dont.know');

$jwt = new JsonWebToken(new Openssl());
$jwtToken = $jwt->create($payload, $secret,'JWS', 'HS256');
```

## Error Handling

When using the library, several exceptions may be thrown in cases of invalid input, such as:

- **InvalidTokenException**: Thrown when the token provided is malformed or invalid, as per the JWT specifications in [**RFC 7519**](https://datatracker.ietf.org/doc/html/rfc7519).
- **InvalidArgumentException**: Raised when an invalid argument is passed to one of the methods, such as an unsupported algorithm or an empty payload.
- **HashErrorException**: Triggered when an issue occurs during the HMAC signing process, ensuring that hashing operations conform to [**RFC 7515**](https://datatracker.ietf.org/doc/html/rfc7515).
- **UnexpectedErrorException**: A general exception that is raised when an unexpected error occurs during encoding, decoding, or encryption processes.
- **CipherErrorException**: Raised when a problem occurs during token encryption or decryption, ensuring compliance with the JWE standard in [**RFC 7516**](https://datatracker.ietf.org/doc/html/rfc7516).

You can catch these exceptions and handle them accordingly in your application:

```php
try {
    $isValid = $jwt->validateToken($token, $key);
} catch (InvalidTokenException $e) {
    // Handle invalid token
} catch (UnsupportedAlgorithmException $e) {
    // Handle unsupported algorithm
}
```

## Supported Algorithms

The `JsonWebToken` class supports a variety of cryptographic algorithms for both JSON Web Signature (JWS) and JSON Web Encryption (JWE). Below are the lists of supported algorithms:

###### JSON Web Signature (JWS) Algorithms

| **Algorithm** | **Description**              | **Support** |
| ------------- | ---------------------------- | ----------- |
| `HS256`       | HMAC with SHA-256            | ✅           |
| `HS384`       | HMAC with SHA-384            | ✅           |
| `HS512`       | HMAC with SHA-512            | ✅           |
| `RS256`       | RSA Signature with SHA-256   | ✅           |
| `RS384`       | RSA Signature with SHA-384   | ✅           |
| `RS512`       | RSA Signature with SHA-512   | ✅           |
| `ES256`       | ECDSA Signature with SHA-256 | ✅           |
| `ES384`       | ECDSA Signature with SHA-384 | ✅           |
| `ES512`       | ECDSA Signature with SHA-512 | ✅           |

###### JSON Web Encryption (JWE) Algorithms

| **Algorithm**      | **Description**                                                                               | **Support** |
| ------------------ | --------------------------------------------------------------------------------------------- | ----------- |
| `RSA-OAEP`         | RSA with Optimal Asymmetric Encryption Padding                                                | ✅           |
| `RSA-OAEP+A192GCM` | RSA-OAEP for key encryption with AES Galois/Counter Mode (GCM) encryption using a 192-bit key | ✅           |
| `RSA-OAEP+A256GCM` | RSA-OAEP for key encryption with AES Galois/Counter Mode (GCM) encryption using a 256-bit key | ✅           |
| `RSA1_5`           | RSAES-PKCS1-v1_5: RSA Encryption Scheme using PKCS#1 v1.5 padding                             | ✅           |
| `A128KW`           | AES Key Wrap with 128-bit key                                                                 | ❌           |
| `A192KW`           | AES Key Wrap with 192-bit key                                                                 | ❌           |
| `A256KW`           | AES Key Wrap with 256-bit key                                                                 | ❌           |
| `A128GCM`          | AES in Galois/Counter Mode with 128-bit key                                                   | ❌           |
| `A192GCM`          | AES in Galois/Counter Mode with 192-bit key                                                   | ❌           |
| `A256GCM`          | AES in Galois/Counter Mode with 256-bit key                                                   | ❌           |

This allows for proper error handling and ensures your application can respond appropriately to invalid or unsupported tokens.

## Running Tests

Unit tests are included in the project to ensure the reliability of the library. These tests cover token creation, validation, and error handling. To run the tests, execute the following command:

```bash
vendor/bin/phpunit
```

All test cases are located in the `tests/` directory and ensure that the class functions correctly under various scenarios.

## Donation

Donations are a great way to support creators and their work. Every contribution helps sustain projects and shows appreciation for their efforts, making a real difference.

| [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R414XGWN) | ![image](https://storage.ko-fi.com/cdn/useruploads/R6R414XGWN/qrcode.png?v=40dee069-2316-462f-8c3f-29825e00fa10?v=2) |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
