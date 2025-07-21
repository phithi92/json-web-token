<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class InvalidSecretLengthException extends CryptoException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct('INVALID_SECRET_LENGTH', $length, $expect);
    }
}
