<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class InvalidKeyTypeException extends PayloadException
{
    public function __construct(string $type = '')
    {
        parent::__construct('INVALID_KEY_TYPE', $type);
    }
}
