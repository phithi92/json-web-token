<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class EmptyFieldException extends CryptoException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::EMPTY_FIELD->getMessage($field));
    }
}
