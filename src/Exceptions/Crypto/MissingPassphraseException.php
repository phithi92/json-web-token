<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class MissingPassphraseException extends CryptoException
{
    public function __construct()
    {
        parent::__construct('MISSING_PASSPHRASE');
    }
}
