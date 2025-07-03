<?php

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Json\ErrorMessagesEnum;

class EncodingException extends JsonException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::DecodingFailed->getMessage($message));
    }
}
