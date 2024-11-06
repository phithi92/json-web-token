<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmErrorMessage;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

class InvalidAsymetricKeyException extends AlgorithmException
{
    public function __construct()
    {
        parent::__construct(AlgorithmErrorMessage::INVALID_ASYMETRIC_KEY->getMessage(openssl_error_string()));
    }
}
