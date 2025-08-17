<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Config;

use RuntimeException;

class AlgorithmConfigFileNotFoundException extends RuntimeException
{
    public function __construct(string $path)
    {
        parent::__construct("Algorithm config file not found at: {$path}");
    }
}
