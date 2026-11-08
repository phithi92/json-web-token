<?php

namespace Phithi92\JsonWebToken\Token\Validator;

use Phithi92\JsonWebToken\Token\Helper\UtcClock;

abstract class AbstractJwtIdValidator implements JwtIdValidatorInterface
{
    public function ttlFromTimestamp(int $timestamp): int
    {
        return max(0, $timestamp - UtcClock::nowTimestampStatic());
    }
}
