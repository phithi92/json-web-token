<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;
use Phithi92\JsonWebToken\Security\Openssl;
use Phithi92\JsonWebToken\Token\JwsSignatureToken;
use Phithi92\JsonWebToken\Token\JweEncodingToken;
use Phithi92\JsonWebToken\PayloadBuilder;
use DateTimeImmutable;

/**
 * JsonWebToken is a final class responsible for creating, validating,
 * and managing JSON Web Tokens (JWTs), specifically JWS (JSON Web Signature)
 * and JWE (JSON Web Encryption) types. This class provides mechanisms to
 * generate tokens, select encryption algorithms, and validate token claims
 * such as expiration and issuance times.
 *
 * It relies on the OpenSSL library for cryptographic operations and enforces
 * specific JWT standards, including payload validation, signature verification,
 * and encryption processes. Various error constants are defined to provide
 * clear messages in case of invalid tokens or JWT-related errors.
 *
 * Key functionalities include:
 * - Creating a JWT (JWS or JWE) with support for different algorithms.
 * - Selecting the best algorithm based on the payload size.
 * - Validating JWT claims such as expiration and issuance time.
 * - Handling Base64URL encoding and decoding for JWT structures.
 *
 * The class ensures proper handling of JWT standards and throws exceptions
 * when tokens are malformed or when cryptographic operations fail.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
final class JsonWebToken
{
    const ERROR_EXPIRED = 'Token has expired';
    const ERROR_UNKNOW_TYPE = 'Unknow jwt type';
    const ERROR_NOT_VALID_YET = 'Token is not valid yet (Not Before claim)';
    const ERROR_ISSUED_IN_FUTURE = 'Token issued in the future';
    const ERROR_DATETIME = 'Invalid date format for value: %s. Error: %s';
    const ERROR_TOKEN_MALFORMT = 'Token is malformt';
    const ERROR_HEADER_JSON_INVALID = 'Header is no valid JSON.';
    const ERROR_HEADER_INVALID = 'Header data is not valid';
    const ERROR_PAYLOAD_JSON_INVALID = 'Header is no valid JSON.';

    /**
     * Constructor for the JsonWebToken class.
     */
    public function __construct(private Openssl $cipher)
    {
    }

    /**
     * Generates a JSON Web Token (JWT) using the specified algorithm.
     *
     * This method creates either a JWS (JSON Web Signature) or a JWE (JSON Web Encryption)
     * token based on the provided payload and key. It validates the payload and checks if
     * the specified algorithm is supported before proceeding with token generation.
     *
     * @param array $payload The data to be signed or encrypted as the JWT payload.
     * @param string $key The secret key (for JWS) or the public key (for JWE) or secret token used for signing or encrypting the token.
     * @param string $algorithm The algorithm to use for token generation, defaults to "RSA-OAEP".
     * @param int|null $keyLength Optionally override the key length for the specified algorithm.
     *
     * @return string The generated JWT as a string.
     *
     * @throws InvalidArgumentException If the payload is empty or if the algorithm is unsupported.
     * @throws InvalidTokenException If the key is invalid or if the signing/encryption process fails.
     */
    public function create(PayloadBuilder $payload_builder, string $key, string $type = 'JWS', string $algorithm = "RSA-OAEP", int $keyLength = null): string
    {
        if (! in_array($type, ['JWS','JWE'])) {
            throw new InvalidArgumentException(self::ERROR_UNKNOW_TYPE);
        }

        $payload = $payload_builder->toArray();

        // Convert the payload to JSON format
        $payloadJson = json_encode($payload);
        if (! $payloadJson) {
            throw new InvalidTokenException(self::ERROR_PAYLOAD_JSON_INVALID);
        }

        //
        if ($type === 'JWS') {
            $Token = new JwsSignatureToken($this->cipher);
        } elseif ($type === 'JWE') {
            $Token = new JweEncodingToken($this->cipher);
        }

        return $Token->createToken($payloadJson, $key, $algorithm);
    }

    /**
     * Selects the best algorithm based on the payload size.
     *
     * @param string $payload The payload to be encrypted.
     * @param string $type The type of algorithm to use, defaults to 'JWE'.
     * @return string The best matching algorithm.
     *
     * @throws Exception If no appropriate algorithm is found for the payload size.
     */
    public function selectBestAlgorithm(string $payload, string $type = 'JWE'): string
    {
        $payloadSize = strlen($payload); // Calculate payload size in bytes

        // Find a matching algorithm that supports the payload size
        foreach ($this->algorithms[$type] as $algo => $details) {
            if ($details['type'] === $type && $payloadSize <= $details['max_payload_size']) {
                return $algo;
            }
        }

        throw new Exception("No suitable algorithm found for the payload size.");
    }

    /**
     * Validates a JSON Web Token (JWT).
     *
     * This method checks the token's signature (for JWS) or decrypts the payload (for JWE),
     * and ensures it has not expired. The algorithm and token type (JWS or JWE) are detected
     * automatically based on the token's header.
     *
     * @param string $encodingToken The JWT to validate.
     * @param string $key The secret key (for JWS) or private key (for JWE) used for verification or decryption.
     *
     * @return bool|array|string The decoded payload if the token is valid, or `false` otherwise.
     *
     * @throws InvalidTokenException If the token is invalid, expired, or decryption fails.
     */
    public function validateToken(string $encodingToken, ?string $key = null): bool
    {
        $tokenData = $this->generateTokenData($encodingToken);
        $tokenParts = count($tokenData);

        if ($tokenParts === 5) {
            $algo = $this->getAlgorithmFromHeader($tokenData[0]['decoded']);
            $encodingToken = new JweEncodingToken($this->cipher);
            $payload = $encodingToken->decrypt($tokenData, $algo);
        } elseif ($tokenParts === 3) {
            $signatureToken = new JwsSignatureToken($this->cipher);
            $payload = $signatureToken->decrypt($tokenData, $key);
        } else {
            throw new InvalidTokenException(self::ERROR_TOKEN_MALFORMT);
        }

        $this->validateJwtClaim($payload);

        return true;
    }

    /**
     * Generates an array containing both the encoded and decoded parts of a JWT token.
     *
     * @param string $token The JWT token string to be processed.
     *
     * @return array An associative array where each token part (header, payload, etc.)
     *               is represented by both its encoded and decoded form.
     *
     * @throws InvalidTokenException If the token is malformed or empty.
     */
    private function generateTokenData(string $token): array
    {
        $parts = explode('.', $token);

        if (empty($parts)) {
            throw new InvalidTokenException(self::ERROR_TOKEN_MALFORMT);
        }

        $result = [];

        foreach ($parts as $key => $value) {
            $result[$key] = [
                'encoded' => $value,
                'decoded' => $this->base64UrlDecode($value)
            ];
        }
        return $result;
    }

    /**
     * Encodes data in Base64 URL format (RFC 7515 standard).
     *
     * @param string $string The data to be encoded.
     * @return string The Base64 URL-encoded string.
     */
    protected function base64UrlEncode(string $string): string
    {
        // Base64 encode the data
        $base64 = base64_encode($string);

        // Replace '+' with '-', '/' with '_', and remove padding '='
        return rtrim(strtr($base64, '+/', '-_'), '=');
    }

    /**
     * Decodes a Base64URL-encoded string.
     *
     * @param string $string The Base64URL-encoded data.
     * @return string The decoded data.
     */
    protected function base64UrlDecode(string $string, $padding = false): string
    {
        $remainder = strlen($string) % 4;
        if ($padding && $remainder > 0) {
            $string .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($string, '-_', '+/'));
    }

    public function getAlgorithmFromHeader(string $headerJson)
    {
        // Decode the header
        $header = json_decode($headerJson, true);

        if (!$header) {
            throw new InvalidTokenException(self::ERROR_HEADER_JSON_INVALID);
        }

        // Automatically detect the algorithm/encoding from the header
        if ($header['alg'] === 'dir' && isset($header['enc']) && ! empty($header['enc'])) {
            return $header['enc'];
        }

        if (isset($header['alg'])) {
            return $header['alg'];
        }

        throw new InvalidTokenException(self::ERROR_HEADER_INVALID);
    }

    /**
    * Validates standard JWT claims like `exp`, `nbf`, and `iat`.
    *
    * @param array $payload The decoded payload from the JWT token.
    * @throws Exception If any claim is invalid (e.g., expired token).
    */
    public function validateJwtClaim(array $payload): void
    {
        $now = time();

        self::checkClaim(isset($payload['exp']) && $payload['exp'] < $now, self::ERROR_EXPIRED);
        self::checkClaim(isset($payload['nbf']) && $payload['nbf'] > $now, self::ERROR_NOT_VALID_YET);
        self::checkClaim(isset($payload['iat']) && $payload['iat'] > $now, self::ERROR_ISSUED_IN_FUTURE);
    }

    /**
     * Converts a datetime string into a Unix timestamp.
     *
     * @param string $datetime A valid datetime string (e.g., 'now', '+1 hour').
     * @return int             The corresponding Unix timestamp.
     * @throws InvalidArgumentException If the datetime string is invalid.
     */
    private function getTimestamp(string $datetime): int
    {
        try {
            $dateTimeObj = new DateTimeImmutable($datetime);
            return $dateTimeObj->getTimestamp();
        } catch (Exception $e) {
            $message = sprintf(self::ERROR_DATETIME, $datetime, $e->getMessage());
            throw new InvalidArgumentException($message);
        }
    }

    /**
     * Checks a claim condition and throws an exception if it is not met.
     *
     * @param bool $condition       The condition to check (e.g., token expired).
     * @param string $errorMessage  The error message to throw if the condition is true.
     * @throws InvalidTokenException If the condition is met, throwing a validation error.
     */
    private static function checkClaim(bool $condition, string $errorMessage): void
    {
        if ($condition) {
            throw new InvalidTokenException($errorMessage);
        }
    }
}
