<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

final class UnexpectedCryptoStageResultException extends CryptoException
{
    public function __construct(string $expected, object $actual)
    {
        parent::__construct('UNEXPECTED_STAGE_RESULT', $expected, get_debug_type($actual));
    }
}
