<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmErrorMessage;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

class InvalidInitializeVectorException extends AlgorithmException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(AlgorithmErrorMessage::INVALID_IV->getMessage($length, $expect));
    }
}
