<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

final class EncryptedPayloadNotSetException extends PayloadException
{
    public function __construct()
    {
        parent::__construct('ENCRYPTED_PAYLOAD_NOT_SET');
    }
}
