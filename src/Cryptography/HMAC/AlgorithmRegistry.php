<?php

namespace Phithi92\JsonWebToken\Cryptography\HMAC;

/**
 * The HmacAlgorithm class provides utilities for working with HMAC (Hash-based Message Authentication Code) algorithms.
 *
 * It defines constants for supported HMAC algorithms and their corresponding block sizes,
 * while also caching the list of available algorithms supported by the system.
 *
 * Key functionalities include retrieving block sizes for specific algorithms and fetching the list of supported
 * algorithms.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
abstract class AlgorithmRegistry
{
    // Supported HMAC algorithms as constants for better readability and consistency.
    protected const ALGO_SHA256 = 'sha256';
    protected const ALGO_SHA384 = 'sha384';
    protected const ALGO_SHA512 = 'sha512';

    // Block sizes for different HMAC algorithms (in bytes).
    protected array $blockSizes = [
        self::ALGO_SHA256 => 32,
        self::ALGO_SHA384 => 64,
        self::ALGO_SHA512 => 128
    ];
}
