<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

class NotBeforeOlderThanExpException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::NBF_BEFORE_IAT->getMessage());
    }
}
