<?php

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Interfaces\SignatureManagerInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

abstract class SignatureService implements SignatureManagerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }

    public function getSigningInput(EncryptedJwtBundle $jwtToken): string
    {
        return implode('.', [
            Base64UrlEncoder::encode($jwtToken->getHeader()->toJson()),
            Base64UrlEncoder::encode($jwtToken->getPayload()->toJson())
        ]);
    }
}
