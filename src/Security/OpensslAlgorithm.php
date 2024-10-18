<?php

namespace Phithi92\JsonWebToken\Security;

/**
 * OpensslAlgorithm is an abstract class that defines common constants, properties, and utility methods
 * related to cryptographic algorithms used in the OpenSSL library.
 * It serves as a base class for managing signature algorithms and key properties.
 *
 * Key functionalities provided by this class:
 * - Constants for widely-used signature algorithms such as ECDSA, RSA-PSS, RSA, and HMAC.
 * - Management of key lengths for different hash algorithms, which are necessary for determining
 *   the minimum key size required for secure cryptographic operations.
 * - Definition of padding overhead for different padding schemes used in RSA encryption (e.g., PKCS#1, OAEP).
 * - Utility methods for extracting algorithm components (type and bit length) and retrieving key lengths.
 *
 * This class is designed to be extended by other classes (like Openssl) that implement
 * specific cryptographic functionality, ensuring a shared structure for handling
 * algorithm types, key sizes, and padding schemes.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
abstract class OpensslAlgorithm
{
    // Constants representing different signature algorithms
    const ECDSA = 'ES';   // Elliptic Curve Digital Signature Algorithm (ECDSA)
    const RSA_PSS = 'PS';  // RSA Probabilistic Signature Scheme (RSA-PSS)
    const RSA = 'RS';      // RSA Signature Algorithm (RSA)
    const HMAC = 'HS';     // HMAC-based Signature Algorithm

    // Array that maps hash algorithms to their recommended key lengths in bits
    protected array $key_length = [
        OPENSSL_ALGO_SHA256 => 2048, // bits
        OPENSSL_ALGO_SHA384 => 3072, // bits
        OPENSSL_ALGO_SHA512 => 4096, // bits
    ];

    // Array that defines padding overhead for different OpenSSL padding schemes
    protected array $padding_length = [
        OPENSSL_PKCS1_PADDING => 11,          // PKCS#1 padding adds 11 bytes
        OPENSSL_PKCS1_OAEP_PADDING => 42,     // PKCS#1 OAEP padding typically adds 42 bytes
        OPENSSL_NO_PADDING => 0               // No padding adds 0 bytes
    ];

    /**
     * Extracts the algorithm type and bit length from a given algorithm string.
     * Example: 'sha256' -> ['sha', 256].
     *
     * @param string $algorithm The algorithm string (e.g., 'sha256').
     * @return array An array containing the algorithm type and bit length.
     * @throws \InvalidArgumentException If the algorithm string is not supported.
     */
    public function extractAlgorithmComponents(string $algorithm): array
    {
        if (!preg_match('/^(sha)(256|384|512)$/', $algorithm, $matches)) {
            throw new \InvalidArgumentException(sprintf('Unsupported algorithm: %s', $algorithm));
        }

        $algorithmType = $matches[1];
        $hashLength = (int) $matches[2];

        return [$algorithmType, $hashLength];
    }

    /**
     * Retrieves the key length in bits for a given algorithm.
     *
     * @param int $algorithm The algorithm constant (e.g., OPENSSL_ALGO_SHA256).
     * @return int The key length in bits, or 0 if the algorithm is not mapped.
     */
    public function getKeyLength(int $algorithm): int
    {
        return $this->key_length[$algorithm] ?? 0;
    }
}
