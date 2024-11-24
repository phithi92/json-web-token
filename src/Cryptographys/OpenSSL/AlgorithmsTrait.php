<?php

namespace Phithi92\JsonWebToken\Cryptographys\OpenSSL;

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
trait AlgorithmsTrait
{
    // Constants representing different signature algorithms
    public const ECDSA = 'ES';   // Elliptic Curve Digital Signature Algorithm (ECDSA)
    public const RSA_PSS = 'PS';  // RSA Probabilistic Signature Scheme (RSA-PSS)
    public const RSA = 'RS';      // RSA Signature Algorithm (RSA)
    public const HMAC = 'HS';     // HMAC-based Signature Algorithm

    /**
     * Array that maps hash algorithms to their recommended key lengths in bits
     * @var array<int,int>
     */
    public array $keyLength = [
        OPENSSL_ALGO_SHA256 => 2048, // bits
        OPENSSL_ALGO_SHA384 => 3072, // bits
        OPENSSL_ALGO_SHA512 => 4096, // bits
    ];

    /**
     * Array that defines padding overhead for different OpenSSL padding schemes
     * @var array<int,int>
     */
    public array $paddingLength = [
        OPENSSL_PKCS1_PADDING => 11,          // PKCS#1 padding adds 11 bytes
        OPENSSL_PKCS1_OAEP_PADDING => 42,     // PKCS#1 OAEP padding typically adds 42 bytes
        OPENSSL_NO_PADDING => 0               // No padding adds 0 bytes
    ];
}
