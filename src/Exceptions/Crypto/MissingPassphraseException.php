<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class MissingPassphraseException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::MISSING_PASSPHRASE->getMessage());
    }
}
