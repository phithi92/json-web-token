<?php

namespace Phithi92\JsonWebToken\Config;

use Phithi92\JsonWebToken\Interfaces\AlgorithmConfigurationInterface;

/**
 * Provides a default configuration loader for algorithms.
 *
 * This class loads algorithm configurations from a PHP file and provides
 * access to individual algorithm settings.
 *
 * @author Phithi92 <development@phillip-thiele.de>
 */
class DefaultAlgorithmConfiguration implements AlgorithmConfigurationInterface
{
    /**
     * @var array<string, array<string, mixed>> Configuration for algorithms.
     */
    private readonly array $config;

    /**
     * Loads algorithm configuration from the given PHP file.
     *
     * @param string $configFile Path to the PHP config file returning an array.
     * @throws \RuntimeException If the config file does not return an array.
     */
    public function __construct(string $configFile = __DIR__ . '/algorithms.php')
    {
        $this->config = require $configFile;
    }

    public function get(string $algorithm): array
    {
        return $this->config[$algorithm] ?? [];
    }

    public function isSupported(string $algorithm): bool
    {
        return isset($this->config[$algorithm]);
    }
}
