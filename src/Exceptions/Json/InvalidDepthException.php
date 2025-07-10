<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Json;

class InvalidDepthException extends JsonException
{
    /**
     * Constructs a DecodingException with a detailed error message from json_last_error_msg().
     */
    public function __construct(int $length)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_LENGTH->getMessage($length));
    }
}
