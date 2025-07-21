<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

class EncodingException extends JsonException
{
    public function __construct(string $message)
    {
        parent::__construct('ENCODING_FAILED', $message);
    }
}
