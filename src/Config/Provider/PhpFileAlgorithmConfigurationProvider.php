<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Config\Provider;

use Phithi92\JsonWebToken\Exceptions\Config\AlgorithmConfigFileNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigFormatException;

use function is_array;
use function is_file;

/**
 * Provides a default configuration loader for algorithms.
 *
 * This class loads algorithm configurations from a PHP file and provides
 * access to individual algorithm settings.
 */
final class PhpFileAlgorithmConfigurationProvider implements AlgorithmConfigurationProvider
{
    private const CONFIG_FILE = __DIR__ . '/../../../resources/algorithms.php';

    /**
     * @var array<string,array<string, array<string, array<string, mixed>>>>
     */
    private static array $cache = [];

    /** @var array<string, array<string, array<string, mixed>>> Configuration for algorithms. */
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
     * @return array<string, array<string, mixed>>
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
     * @return array<string, array<string, array<string, mixed>>>
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

        self::assertValidConfiguration($config, $configFile);

        /** @var array<string, array<string, array<string, mixed>>> $config */
        return self::$cache[$configFile] = $config;
    }

    /**
     * @throws InvalidAlgorithmConfigFormatException
     */
    private static function assertValidConfiguration(mixed $config, string $configFile): void
    {
        if (! is_array($config)) {
            throw new InvalidAlgorithmConfigFormatException(
                sprintf('Configuration file "%s" must return an array.', $configFile)
            );
        }

        foreach ($config as $algorithm => $operations) {
            if (! is_string($algorithm) || ! is_array($operations)) {
                throw new InvalidAlgorithmConfigFormatException(
                    sprintf('Invalid configuration structure in "%s".', $configFile)
                );
            }

            foreach ($operations as $option => $value) {
                if (! is_string($option)) {
                    throw new InvalidAlgorithmConfigFormatException(
                        sprintf(
                            'Invalid option key for algorithm "%s" operation "%s" in "%s".',
                            $algorithm,
                            $option,
                            $configFile
                        )
                    );
                }

                // value is mixed -> no validation
            }
        }
    }
}
