<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class InvalidAsymmetricKeyLength extends CryptoException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct('INVALID_ASYMETRIC_KEY_LENGTH', $length, $expect);
    }
}
