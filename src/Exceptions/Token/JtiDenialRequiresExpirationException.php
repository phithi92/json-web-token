<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class JtiDenialRequiresExpirationException extends TokenException
{
    public function __construct()
    {
        parent::__construct('JTI_REQUIRES_EXP');
    }
}
