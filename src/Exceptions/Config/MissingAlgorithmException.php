<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Config;

use RuntimeException;

class MissingAlgorithmException extends RuntimeException
{
    public function __construct(string $source)
    {
        parent::__construct(
            sprintf('Missing algorithm (source: %s).', $source)
        );
    }    
}
