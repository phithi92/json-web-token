<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Config;

use Phithi92\JsonWebToken\Interfaces\AlgorithmConfigurationInterface;

/**
 * Provides a default configuration loader for algorithms.
 *
 * This class loads algorithm configurations from a PHP file and provides
 * access to individual algorithm settings.
 */
class DefaultAlgorithmConfiguration implements AlgorithmConfigurationInterface
{
    /**
     * @var array<string, array<string, string>> Configuration for algorithms.
     */
    private readonly array $config;

    /**
     * Loads algorithm configuration from the given PHP file.
     *
     * @param string $configFile Path to the PHP config file returning an array.
     *
     * @throws \RuntimeException If the config file does not return an array.
     */
    public function __construct(string $configFile = __DIR__ . '/algorithms.php')
    {
        /** @var array<string, array<string, string>> $config */
        $config = $this->loadedAndValidatedConfiguration($configFile);

        $this->config = $config;
    }

    /**
     * @return array<string, string>
     */
    public function get(string $algorithm): array
    {
        return $this->config[$algorithm] ?? [];
    }

    public function isSupported(string $algorithm): bool
    {
        return isset($this->config[$algorithm]);
    }

    private function loadedAndValidatedConfiguration(string $configFile): array
    {
        if (! is_file($configFile)) {
            throw new \RuntimeException("Algorithm config file not found: {$configFile}");
        }

        $config = include $configFile;
        if (! is_array($config)) {
            throw new \RuntimeException('Algorithm config file must return an array.');
        }

        return $config;
    }
}
