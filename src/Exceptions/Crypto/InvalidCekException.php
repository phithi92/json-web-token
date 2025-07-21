<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class InvalidCekException extends CryptoException
{
    public function __construct(string $message)
    {
        parent::__construct('INVALID_CEK', $message);
    }
}
