<?php

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtEncryptionData;

/**
 *
 * @author phillipthiele
 */
interface EncryptedJwtInterface
{
    public function getHeader(): JwtHeader;
    public function getPayload(): JwtPayload;
    public function getSignature(): ?string;
    public function getEncryption(): JwtEncryptionData;
}
