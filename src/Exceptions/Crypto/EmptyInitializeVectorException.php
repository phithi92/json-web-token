<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class EmptyInitializeVectorException extends CryptoException
{
    public function __construct()
    {
        parent::__construct('EMPTY_IV');
    }
}
