<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;

/**
 * Description of InvalidPrivateClaimException
 *
 * @author phillipthiele
 */
class MissingPrivateClaimException extends TokenException
{
    public function __construct(string $claim)
    {
        parent::__construct(ErrorMessagesEnum::MISSING_PRIVATE_CLAIM->getMessage($claim));
    }
}
