<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmErrorMessage;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\AlgorithmException;

class MissingPassphraseException extends AlgorithmException
{
    public function __construct()
    {
        parent::__construct(AlgorithmErrorMessage::MISSING_PASSPHRASE->getMessage());
    }
}
