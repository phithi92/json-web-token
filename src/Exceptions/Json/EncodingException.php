<?php

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Phithi92\JsonWebToken\Exceptions\Json\JsonException;
use Phithi92\JsonWebToken\Exceptions\Json\ErrorMessagesEnum;

/**
 * Exception thrown when JSON encoding fails in the JsonEncoder.
 *
 * This exception captures the error message provided by PHP's JSON encoding function,
 * making it easier to diagnose encoding issues. It extends the JsonException base class,
 * allowing it to be caught with other JSON-related exceptions.
 *
 * @package json-web-token\Exception\Json
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
class EncodingException extends JsonException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::DecodingFailed->getMessage($message));
    }
}
