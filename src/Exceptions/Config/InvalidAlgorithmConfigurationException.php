<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Config;

use RuntimeException;

class InvalidAlgorithmConfigurationException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct("Invalid algorithm configuration: expected token_type, alg, and enc to be scalar values.");
    }
}
