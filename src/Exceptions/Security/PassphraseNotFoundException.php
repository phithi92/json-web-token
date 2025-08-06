<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exception\Security;

use Phithi92\JsonWebToken\Exceptions\Payload\SecurityException;

final class PassphraseNotFoundException extends SecurityException
{
    public function __construct(string $kid)
    {
        parent::__construct('PASSPHRASE_NOT_FOUND', $kid);
    }
}
