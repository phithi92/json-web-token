<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmErrorMessage;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

class InvalidAsymetricKeyLength extends AlgorithmException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(AlgorithmErrorMessage::INVALID_ASYMETRIC_KEY_LENGTH->getMessage($length, $expect));
    }
}
