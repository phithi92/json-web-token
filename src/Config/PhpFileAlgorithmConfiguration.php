<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Config;

use Phithi92\JsonWebToken\Exceptions\Config\AlgorithmConfigFileNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigFormatException;
use Phithi92\JsonWebToken\Interfaces\AlgorithmConfigurationProvider;

use function is_array;
use function is_file;

/**
 * Provides a default configuration loader for algorithms.
 *
 * This class loads algorithm configurations from a PHP file and provides
 * access to individual algorithm settings.
 */
final class PhpFileAlgorithmConfiguration implements AlgorithmConfigurationProvider
{
    private const CONFIG_FILE = __DIR__ . '/algorithms.php';

    /**
     * @var array<string, array<string, array<string, string>>>
     */
    private static array $cache = [];

    /** @var array<string, array<string, string>> Configuration for algorithms. */
    private readonly array $config;

    /**
     * Loads algorithm configuration from the given PHP file.
     *
     * @param string $configFile  path to the PHP config file returning an array
     * @param bool   $forceReload whether to bypass the static cache (useful for tests)
     *
     * @throws AlgorithmConfigFileNotFoundException
     * @throws InvalidAlgorithmConfigFormatException
     */
    public function __construct(string $configFile = self::CONFIG_FILE, bool $forceReload = false)
    {
        $this->config = $this->loadedAndValidatedConfiguration($configFile, $forceReload);
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

    /**
     * @return array<string, array<string, string>>
     *
     * @throws AlgorithmConfigFileNotFoundException
     * @throws InvalidAlgorithmConfigFormatException
     */
    private function loadedAndValidatedConfiguration(
        string $configFile,
        bool $forceReload = false,
    ): array {
        if (! $forceReload && isset(self::$cache[$configFile])) {
            return self::$cache[$configFile];
        }

        if (! is_file($configFile)) {
            throw new AlgorithmConfigFileNotFoundException($configFile);
        }

        $config = include $configFile;
        if (! is_array($config)) {
            throw new InvalidAlgorithmConfigFormatException($configFile);
        }

        /** @var array<string, array<string, string>> $config */
        return self::$cache[$configFile] = $config;
    }
}
