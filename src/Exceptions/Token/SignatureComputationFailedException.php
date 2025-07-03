<?php

namespace Phithi92\JsonWebToken\Exceptions\Signing;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

class SignatureComputationFailedException extends TokenException
{
    public function __construct(string $opensslError)
    {
        parent::__construct(ErrorMessagesEnum::COMPUTATION_FAILED->getMessage($opensslError));
    }
}
