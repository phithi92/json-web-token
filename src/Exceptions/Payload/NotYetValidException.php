<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class NotYetValidException extends PayloadException
{
    public function __construct()
    {
        parent::__construct('FUTURE_TOKEN');
    }
}
