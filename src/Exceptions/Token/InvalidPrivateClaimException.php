<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;

/**
 * Description of InvalidPrivateClaimException
 *
 * @author phillipthiele
 */
class InvalidPrivateClaimException extends TokenException
{
    public function __construct(string $claim, string $expected)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_PRIVATE_CLAIM->getMessage($claim, $expected));
    }
}
