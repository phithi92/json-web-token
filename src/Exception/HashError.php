<?php

namespace Phithi92\JsonWebToken\Exception;

use Phithi92\JsonWebToken\Exception\HashErrorEnum;
use Exception;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class HashError extends Exception
{
    public static function unsupportedAlgorithm(string $algorithm): self
    {
        $message = sprintf(HashErrorEnum::UNSUPPORTED_ALGORITHM, $algorithm);
        return self::generateException($message);
    }

    /**
     * Helper method to create a new exception instance.
     *
     * @param  string $message - The error message for the exception.
     * @return self
     */
    private static function generateException(string $message): self
    {
        return new self($message);
    }
}
