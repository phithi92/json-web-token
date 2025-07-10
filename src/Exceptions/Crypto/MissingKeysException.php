<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class MissingKeysException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::MISSING_KEYS->getMessage());
    }
}
