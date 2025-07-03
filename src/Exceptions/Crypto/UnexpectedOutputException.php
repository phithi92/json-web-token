<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;

/**
 * Exception thrown when an unsupported algorithm is encountered.
 *
 * This exception signals that a specified algorithm is not supported by the application.
 *
 * @package json-web-token\Exception\Json
 * @version 1.0.0
 * @since   1.0.0
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
class UnexpectedOutputException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::UNEXPECTED_OUTPUT->getMessage());
    }
}
