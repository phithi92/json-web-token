<?php

namespace Phithi92\JsonWebToken\Exceptions\Cryptographys;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\CryptographyException;

class MissingKeysException extends CryptographyException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::MISSING_KEYS->getMessage());
    }
}
