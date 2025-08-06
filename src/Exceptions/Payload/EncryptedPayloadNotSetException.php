<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Token;

final class EncryptedPayloadNotSetException extends TokenException
{
    public function __construct()
    {
        parent::__construct('ENCRYPTED_PAYLOAD_NOT_SET');
    }
}
