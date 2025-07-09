<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtEncryptionData;

interface EncryptedJwtInterface
{
    public function getHeader(): JwtHeader;
    public function getPayload(): JwtPayload;
    public function getSignature(): ?string;
    public function getEncryption(): JwtEncryptionData;
}
