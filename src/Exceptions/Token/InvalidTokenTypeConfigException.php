<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

class InvalidTokenTypeConfigException extends TokenException
{
    public function __construct()
    {
        parent::__construct('INVALID_CONFIG_TOKEN_TYPE');
    }
}
