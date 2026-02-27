<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class JtiDenialRequiresExpirationException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct('JTI_REQUIRES_EXP', $message);
    }
}
