<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\KeyManagement;

use Override;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\UnexpectedCryptoStageResultException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;

class CekResultHandler implements CryptoStageResultHandlerInterface
{
    public function isSupported(CryptoOperationDirection $direction): bool
    {
        return match($direction) {
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
        if (! $result instanceof CekHandlerResult) {
            throw new UnexpectedCryptoStageResultException(CekHandlerResult::class, $result);
        }

        $encryptionData = $this->resolveEncryptionData($bundle, $result);

        return $bundle->setEncryption($encryptionData);
    }

    private function resolveEncryptionData(JwtBundle $bundle, CekHandlerResult $result): JwtEncryptionData
    {
        return $bundle->hasEncryption()
            ? $bundle->getEncryption()->withCek($result->getContentEncryptionKey())
            : new JwtEncryptionData(cek: $result->getContentEncryptionKey());
    }
}
