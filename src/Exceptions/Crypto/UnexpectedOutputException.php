<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class UnexpectedOutputException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::UNEXPECTED_OUTPUT->getMessage());
    }
}
