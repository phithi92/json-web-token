<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Exception;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class UnsupportedAlgorithmException extends Exception
{
    public function __construct(string $algorithm): Exception
    {
        return parent::__construct('Unsupported Algorithm ' . $algorithm);
    }
}
