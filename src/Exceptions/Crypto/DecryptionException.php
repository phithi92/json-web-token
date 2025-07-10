<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class DecryptionException extends CryptoException
{
    public function __construct(string $errorMessage)
    {
        parent::__construct(ErrorMessagesEnum::DECRYPTION_FAILED->getMessage($errorMessage));
    }
}
