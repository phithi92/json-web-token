<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

interface AlgorithmConfigurationInterface
{
    /**
     * Returns the configuration array for the given algorithm.
     *
     * @param string $algorithm The name of the algorithm.
     *
     * @return array<string, array<string, string>|string>
     * The configuration array if found, or an empty array if the algorithm is not supported.
     */
    public function get(string $algorithm): array;

    /**
     * Check if given algorithm is supported
     */
    public function isSupported(string $algorithm): bool;
}
