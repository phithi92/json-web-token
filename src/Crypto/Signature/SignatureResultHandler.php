<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Override;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\UnexpectedCryptoStageResultException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;

class SignatureResultHandler implements CryptoStageResultHandlerInterface
{
    public function isSupported(CryptoOperationDirection $direction): bool
    {
        return match ($direction) {
            CryptoOperationDirection::Perform => true,
            CryptoOperationDirection::Reverse => false
        };
    }

    #[Override]
    public function handle(
        CryptoOperationDirection $operation,
        CryptoStageResultInterface $result,
        JwtBundle $bundle
    ): JwtBundle {
        if (! $result instanceof SignatureHandlerResult) {
            throw new UnexpectedCryptoStageResultException(SignatureHandlerResult::class, $result);
        }

        $signature = $this->resolveSignature($result);
        return $bundle->setSignature($signature);
    }

    private function resolveSignature(SignatureHandlerResult $result): JwtSignature
    {
        return $result->getSignature();
    }
}
