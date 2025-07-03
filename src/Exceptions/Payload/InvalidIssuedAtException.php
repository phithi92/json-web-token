<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

class InvalidIssuedAtException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::EXPIRED_PAYLOAD->getMessage());
    }
}
