<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class ClaimAlreadyExistsException extends PayloadException
{
    public function __construct(string $name)
    {
        parent::__construct('CLAIM_ALREADY_EXISTS', $name);
    }
}
