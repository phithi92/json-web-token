<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class MissingKeysException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::MISSING_KEYS->getMessage());
    }
}
