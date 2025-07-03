<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class DecryptionException extends CryptoException
{
    public function __construct(string $errorMessage)
    {
        parent::__construct(ErrorMessagesEnum::DECRYPTION_FAILED->getMessage($errorMessage));
    }
}
