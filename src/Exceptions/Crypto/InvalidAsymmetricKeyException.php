<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class InvalidAsymmetricKeyException extends CryptoException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_ASYMETRIC_KEY->getMessage($message));
    }
}
