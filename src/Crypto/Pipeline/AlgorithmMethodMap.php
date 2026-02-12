<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

final class AlgorithmMethodMap
{
    private const METHOD_MAP = [
        CryptoProcessingStage::Signature->name => [
            CryptoOperationDirection::Perform->name => 'computeSignature',
            CryptoOperationDirection::Reverse->name => 'validateSignature',
        ],
        CryptoProcessingStage::Cek->name => [
            CryptoOperationDirection::Perform->name => 'initializeCek'
        ],
        CryptoProcessingStage::Iv->name => [
            CryptoOperationDirection::Perform->name => 'initializeIv',
            CryptoOperationDirection::Reverse->name => 'validateIv',
        ],
        CryptoProcessingStage::Key->name => [
            CryptoOperationDirection::Perform->name => 'wrapKey',
            CryptoOperationDirection::Reverse->name => 'unwrapKey',
        ],
        CryptoProcessingStage::Payload->name => [
            CryptoOperationDirection::Perform->name => 'encryptPayload',
            CryptoOperationDirection::Reverse->name => 'decryptPayload',
        ],
    ];

    public function supports(
        CryptoProcessingStage $stage,
        CryptoOperationDirection $direction
    ): bool {
        return isset(self::METHOD_MAP[$stage->name][$direction->name]);
    }

    /**
     * Resolves the method name that should be called on a handler
     * based on its type and the operation direction.
     */
    public function resolve(CryptoProcessingStage $target, CryptoOperationDirection $operation): string
    {
        return self::METHOD_MAP[$target->name][$operation->name];
    }
}
