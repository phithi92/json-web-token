<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

class MalformedTokenException extends JsonException
{
    public function __construct()
    {
        parent::__construct('MALFORMED');
    }
}
