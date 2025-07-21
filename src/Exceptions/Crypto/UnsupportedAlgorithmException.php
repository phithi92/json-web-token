<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class UnsupportedAlgorithmException extends CryptoException
{
    public function __construct(string $algorithm)
    {
        parent::__construct('UNSUPPORTED', $algorithm);
    }
}
