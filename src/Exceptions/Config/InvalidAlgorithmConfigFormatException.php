<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Config;

use RuntimeException;

class InvalidAlgorithmConfigFormatException extends RuntimeException
{
    public function __construct(string $path)
    {
        parent::__construct("Algorithm config file must return an array: {$path}");
    }
}
