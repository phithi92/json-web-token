<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class MissingPrivateClaimException extends TokenException
{
    public function __construct(string $claim)
    {
        parent::__construct(ErrorMessagesEnum::MISSING_PRIVATE_CLAIM->getMessage($claim));
    }
}
