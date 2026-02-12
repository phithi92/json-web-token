<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;
use Phithi92\JsonWebToken\Token\JwtSignature;

class SignatureHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly JwtSignature $signature
    ) {
    }

    public function getSignature(): JwtSignature
    {
        return $this->signature;
    }
}
