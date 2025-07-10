<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class NotBeforeOlderThanExpException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::NBF_BEFORE_IAT->getMessage());
    }
}
