<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidIssuedAtException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::EXPIRED_PAYLOAD->getMessage());
    }
}
