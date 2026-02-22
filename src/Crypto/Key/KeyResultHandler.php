<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Override;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\UnexpectedCryptoStageResultException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;

class KeyResultHandler implements CryptoStageResultHandlerInterface
{
    public function isSupported(CryptoOperationDirection $direction): bool
    {
        return true;
    }

    #[Override]
    public function handle(
        CryptoOperationDirection $operation,
        CryptoStageResultInterface $result,
        JwtBundle $bundle
    ): JwtBundle {
        $encryptionData = match ($operation) {
            CryptoOperationDirection::Perform => $this->handlePerformOperation($bundle, $result),
            CryptoOperationDirection::Reverse => $this->handleReverseOperation($bundle, $result),
        };

        return $bundle->setEncryption($encryptionData);
    }

    private function handlePerformOperation(JwtBundle $bundle, CryptoStageResultInterface $result): JwtEncryptionData
    {
        if (! $result instanceof KeyWrapperHandlerResult) {
            throw new UnexpectedCryptoStageResultException(KeyWrapperHandlerResult::class, $result);
        }

        return $bundle->getEncryption()->withEncryptedKey($result->getWrappedKey());
    }

    private function handleReverseOperation(JwtBundle $bundle, CryptoStageResultInterface $result): JwtEncryptionData
    {
        if (! $result instanceof KeyUnwrapperHandlerResult) {
            throw new UnexpectedCryptoStageResultException(KeyUnwrapperHandlerResult::class, $result);
        }

        return $bundle->getEncryption()->withCek($result->getContentEncryptionKey());
    }
}
