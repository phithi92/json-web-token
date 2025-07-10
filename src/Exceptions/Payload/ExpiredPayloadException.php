<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class ExpiredPayloadException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::PAYLOAD_EXPIRED->getMessage());
    }
}
