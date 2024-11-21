<?php

namespace Phithi92\JsonWebToken\Exceptions\Cryptographys;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\CryptographyException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\ErrorMessagesEnum;

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
class UnsupportedAlgorithmException extends CryptographyException
{
    public function __construct(string $algorithm)
    {
        parent::__construct(ErrorMessagesEnum::UNSUPPORTED->getMessage($algorithm));
    }
}
