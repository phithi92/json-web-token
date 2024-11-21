<?php

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Json\ErrorMessagesEnum;

/**
 * Exception thrown when JSON decoding fails in the JsonEncoder.
 *
 * This exception is part of the JSON handling utilities and indicates
 * that decoding the JSON string was unsuccessful.
 *
 * @package json-web-token\Exception\Json
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
class DecodingException extends JsonException
{
    /**
     * Constructs a DecodingException with a detailed error message from json_last_error_msg().
     */
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::DecodingFailed->getMessage($message));
    }
}
