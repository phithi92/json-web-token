<?php

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exception\InvalidTokenException;
use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Hash\HashInterface;
use Phithi92\JsonWebToken\Security\Openssl;

/**
 * Abstract class Token
 *
 * This class serves as the base for handling JSON Web Tokens (JWT), providing core functionality
 * for encoding, decoding, and managing both JWS (JSON Web Signature) and JWE (JSON Web Encryption) tokens.
 * It defines common methods such as Base64URL encoding/decoding, token building, and algorithm support.
 *
 * Subclasses or traits may extend this abstract class to implement specific behaviors related
 * to JWS or JWE tokens, utilizing the defined padding schemes and supported algorithms.
 *
 * Key features:
 * - Supports both symmetric (e.g., HMAC) and asymmetric (e.g., RSA) algorithms for signing/encryption.
 * - Implements helper methods for token structure management and encryption validation.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
abstract class JwtBase
{
    const INVALID_TOKEN_FORMAT = 'Token schema invalid. Explode token failed';
    const INVALID_TOKEN_HEADER_DATA = 'Header data are not valid';
    const ERROR_JSON_ENCODE = 'Encoding failed. %s';
    const ERROR_ALGORITHM_UNSUPPORTED = 'Unsupported algorithm %s';
    const ERROR_INVALID_JSON_ENCODING = 'JSON encoding failed. %s';
    const ERROR_INVALID_JSON_DECODING = 'JSON decoding failed. %s';

    protected array $algorithms = [];

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

    /**
     * Builds and encodes the JWT token from its parts.
     *
     * @param array $parts The parts of the JWT (header, payload, signature).
     * @return string The final JWT string.
     */
    protected function buildAndEncodeToken(array $parts): string
    {
        return implode('.', array_map([$this, 'base64UrlEncode'], $parts));
    }

    /**
     * Splits and decodes the JWT token into its individual parts.
     *
     * @param string $token The JWT token.
     * @return array The decoded token parts (header, payload, signature).
     *
     * @throws InvalidTokenException If the token is malformed.
     */
    protected function generateTokenData(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) < 3) { // Minimum of 3 parts for JWS and JWE
            throw new InvalidArgumentException(self::INVALID_TOKEN_FORMAT);
        }

        return [
            'encoded' => $parts,
            'decoded' => array_map([$this, 'base64UrlDecode'], $parts)
        ];
    }

    /**
     *
     * @param string $json
     * @return array
     * @throws InvalidTokenException
     */
    protected function safeJsonDecode(string $json): array
    {
        $decoded = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidTokenException(sprintf(self::ERROR_INVALID_JSON_ENCODING, json_last_error_msg()));
        }
        return $decoded;
    }

    protected function safeJsonEncode(array $array): string
    {
        $encoded = json_encode($array);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidTokenException(sprintf(self::ERROR_INVALID_JSON_DECODING, json_last_error_msg()));
        }
        return $encoded;
    }

    /**
     * Extracts the algorithm from the JWT header.
     *
     * @param array $header The decoded header of the JWT.
     * @return string The detected algorithm.
     * @throws InvalidTokenException If the algorithm is not found or invalid.
     */
    protected function getAlgorithmFromHeader(array $header): string
    {
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidTokenException(sprintf(self::ERROR_JSON_ENCODE, json_last_error_msg()));
        }

        // Automatically detect the algorithm/encoding from the header
        if ($header['alg'] === 'dir' && isset($header['enc']) && ! empty($header['enc'])) {
            return $header['enc'];
        }

        if (isset($header['alg'])) {
            return $header['alg'];
        }

        throw new InvalidTokenException(self::INVALID_TOKEN_HEADER_DATA);
    }

    /**
     * Retrieves the algorithm data for the specified algorithm.
     *
     * This method first checks if the provided algorithm is missing or invalid.
     * If the algorithm is not 'dir' or is not found in the list of supported algorithms,
     * it throws an InvalidTokenException. If the algorithm is valid, the corresponding
     * configuration details are returned.
     *
     * @param string $algorithm The algorithm to retrieve data for.
     * @return array The algorithm's configuration details.
     * @throws InvalidTokenException If the algorithm is missing or unsupported.
     */
    protected function getAlgorithmData(string $algorithm): array
    {
        if (empty($algorithm)) {
            throw new InvalidTokenException(self::INVALID_TOKEN_HEADER_DATA);
        }

        if (! array_key_exists($algorithm, $this->algorithms)) {
            throw new InvalidTokenException(self::ERROR_ALGORITHM_UNSUPPORTED);
        }

        return $this->algorithms[$algorithm];
    }

//    abstract public function validateToken(array $tokenParts): bool;
}
