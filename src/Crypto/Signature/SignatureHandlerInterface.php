<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

interface SignatureHandlerInterface
{
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void;

    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult;
}
