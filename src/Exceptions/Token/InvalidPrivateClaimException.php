<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidPrivateClaimException extends TokenException
{
    public function __construct(string $claim, string $expected)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_PRIVATE_CLAIM->getMessage($claim, $expected));
    }
}
