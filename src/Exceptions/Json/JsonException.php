<?php

namespace Phithi92\JsonWebToken\Exceptions\Json;

use Exception;

/**
 * Base exception class for JSON-related errors.
 *
 * Provides optional fields to capture additional context about the error, which
 * can be useful for debugging or logging.
 *
 * @package json-web-token\Exception\Json
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
class JsonException extends Exception
{
}
