<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class NotBeforeOlderThanIatException extends PayloadException
{
    public function __construct()
    {
        parent::__construct('NBF_BEFORE_IAT');
    }
}
