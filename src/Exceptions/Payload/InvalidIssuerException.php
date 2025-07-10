<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidIssuerException extends PayloadException
{
    public function __construct(string $expectedIssuer, string $issuer)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_ISSUER->getMessage($expectedIssuer, $issuer));
    }
}
