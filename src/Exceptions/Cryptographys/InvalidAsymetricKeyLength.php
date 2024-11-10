<?php

namespace Phithi92\JsonWebToken\Exceptions\Cryptographys;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\CryptographyException;

class InvalidAsymetricKeyLength extends CryptographyException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_ASYMETRIC_KEY_LENGTH->getMessage($length, $expect));
    }
}
