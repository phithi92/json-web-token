<?php

namespace Phithi92\JsonWebToken\Interfaces;

interface AlgorithmConfigurationInterface
{
    /**
     * Returns the configuration array for the given algorithm.
     *
     * @param string $algorithm The name of the algorithm.
     * @return array<string, mixed> The configuration array if found, or an empty array if the algorithm is not supported.
     */
    public function get(string $algorithm): array;

    /**
     *
     * @param string $algorithm
     * @return bool
     */
    public function isSupported(string $algorithm): bool;
}
