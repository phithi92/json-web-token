<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmErrorMessage;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

class EncryptionVerificationException extends AlgorithmException
{
    public function __construct()
    {
        parent::__construct(AlgorithmErrorMessage::VERIFICATION_FAILED->getMessage(openssl_error_string()));
    }
}
