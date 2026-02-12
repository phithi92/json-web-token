<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\ContentEncryption;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\UnexpectedCryptoStageResultException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;

final class ContentEncryptionResultHandler implements CryptoStageResultHandlerInterface
{
    public function isSupported(CryptoOperationDirection $direction): bool
    {
        return true;
    }

    public function handle(
        CryptoOperationDirection $operation,
        CryptoStageResultInterface $result,
        JwtBundle $bundle,
    ): JwtBundle {
        return match ($operation) {
            CryptoOperationDirection::Perform => $this->handlePerformOperation($bundle, $result),
            CryptoOperationDirection::Reverse => $this->handleDecodeOperation($bundle, $result),
        };
    }

    /**
     * Handles the perform operation (encryption).
     *
     * @param CryptoStageResultInterface $result The operation result
     * @param JwtBundle $bundle The JWT bundle
     *
     * @return JwtBundle The modified JWT bundle
     */
    private function handlePerformOperation(JwtBundle $bundle, CryptoStageResultInterface $result): JwtBundle
    {
        if (! $result instanceof EncryptionHandlerResult) {
            throw new UnexpectedCryptoStageResultException(EncryptionHandlerResult::class, $result);
        }

        $bundle->getPayload()->setEncryptedPayload($result->getCiphertext());
        $bundle->setEncryption($bundle->getEncryption()->withAuthTag($result->getAuthenticationTag()));

        return $bundle;
    }

    /**
     * Handles the decode operation.
     *
     * @param CryptoStageResultInterface $result The operation result
     * @param JwtBundle $bundle The JWT bundle
     *
     * @return JwtBundle The modified JWT bundle
     */
    private function handleDecodeOperation(JwtBundle $bundle, CryptoStageResultInterface $result): JwtBundle
    {
        if (! $result instanceof DecryptionHandlerResult) {
            throw new UnexpectedCryptoStageResultException(DecryptionHandlerResult::class, $result);
        }

        JwtPayloadJsonCodec::decodeStaticInto($result->getPlaintext(), $bundle->getPayload());

        return $bundle;
    }
}
