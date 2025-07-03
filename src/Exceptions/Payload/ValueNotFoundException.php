<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

class ValueNotFoundException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::VALUE_NOT_FOUND->getMessage($field));
    }
}
