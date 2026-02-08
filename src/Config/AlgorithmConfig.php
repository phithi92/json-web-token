<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Config;

use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigurationException;

use function is_string;

final class AlgorithmConfig
{
    /**
     * @param array<string, mixed> $config
     */
    public function __construct(private array $config)
    {
    }

    public function hashAlgorithm(): string
    {
        $v = $this->config['hash_algorithm'] ?? null;
        return is_string($v) && $v !== '' ? $v : throw new InvalidAlgorithmConfigurationException();
    }
}
