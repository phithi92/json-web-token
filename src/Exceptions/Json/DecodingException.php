<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

class DecodingException extends JsonException
{
    /**
     * Constructs a DecodingException with a detailed error message from json_last_error_msg().
     */
    public function __construct(string $message)
    {
        parent::__construct('DECODING_FAILED', $message);
    }
}
