<?php

namespace Phithi92\JsonWebToken\Exception\Json;

use Phithi92\JsonWebToken\Exception\Json\JsonException;
use Exception;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EncodingException extends JsonException
{
    public function __construct(): Exception
    {
        $message = json_last_error_msg();
        return parent::__construct("JSON encoding failed: $message");
    }
}
