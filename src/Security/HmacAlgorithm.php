<?php

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;

/**
 * The HmacAlgorithm class provides utilities for working with HMAC (Hash-based Message Authentication Code) algorithms.
 *
 * It defines constants for supported HMAC algorithms and their corresponding block sizes,
 * while also caching the list of available algorithms supported by the system.
 *
 * Key functionalities include retrieving block sizes for specific algorithms and fetching the list of supported algorithms.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
abstract class HmacAlgorithm
{
    const ERROR_ALGORITHM_UNSUPPORTED = "Unsupported HMAC algorithm: %s";

    // Supported HMAC algorithms as constants for better readability and consistency.
    const ALGO_SHA256 = 'sha256';
    const ALGO_SHA384 = 'sha384';
    const ALGO_SHA512 = 'sha512';

    // Block sizes for different HMAC algorithms (in bytes).
    private array $blockSizes = [
        self::ALGO_SHA256 => 64,
        self::ALGO_SHA384 => 64,
        self::ALGO_SHA512 => 128
    ];

    // Cached list of supported algorithms, initialized lazily.
    private ?array $supportedAlgorithms = null;

    /**
     * Retrieves the block size for the given HMAC algorithm.
     *
     * This method returns the block size associated with the selected HMAC algorithm.
     * If the algorithm is unsupported, it throws an exception.
     *
     * @param string $algorithm The HMAC algorithm (e.g., 'sha256').
     *
     * @return int The block size in bytes.
     *
     * @throws InvalidArgumentException If the algorithm is not supported.
     */
    protected function getHmacBlockSize(string $algorithm): int
    {
        // Ensure the algorithm is in lowercase.
        $algorithm = strtolower($algorithm);

        // Return the block size for the known algorithm or throw an exception if unsupported.
        if (isset($this->blockSizes[$algorithm])) {
            return $this->blockSizes[$algorithm];
        }

        throw new InvalidArgumentException(sprintf(self::ERROR_ALGORITHM_UNSUPPORTED, $algorithm));
    }

    /**
     * Retrieves the list of supported HMAC algorithms.
     *
     * This method lazily initializes and caches the list of supported algorithms using
     * PHP's `hash_hmac_algos()` function.
     *
     * @return array The list of supported algorithms.
     */
    public function getSupportedAlgorithms(): array
    {
        if ($this->supportedAlgorithms === null) {
            $this->supportedAlgorithms = hash_hmac_algos();
        }

        return $this->supportedAlgorithms;
    }
}
