<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

class EncryptedPayloadAlreadySetException extends PayloadException
{
    public function __construct()
    {
        parent::__construct('ENCRYPTED_PAYLOAD_ALREADY_SET');
    }
}
