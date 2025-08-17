<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

class MalformedUtf8Exception extends JsonException
{
    public function __construct()
    {
        parent::__construct('MALFORMED_UTF8');
    }
}
