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
            CryptoOperationDirection::Perform->name => 'initializeCek',
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

    /**
     * Determines whether a handler method is configured for the given processing stage and operation direction.
     *
     * The lookup is performed against the internal method map. A combination is considered supported
     * if a method name exists for the provided stage and direction.
     *
     * @return bool True if a matching handler method is configured; otherwise false.
     */
    public function supports(AlgorithmInvocation $invocation): bool
    {
        return isset(self::METHOD_MAP[$invocation->target->name][$invocation->operation->name]);
    }

    /**
     * Resolves the handler method name for the given algorithm invocation.
     *
     * @param AlgorithmInvocation $invocation The invocation context containing target and operation.
     *
     * @return string|null The handler method name to invoke (e.g. "encryptPayload"), or null if not defined.
     */
    public function resolve(AlgorithmInvocation $invocation): ?string
    {
        return self::METHOD_MAP[$invocation->target->name][$invocation->operation->name] ?? null;
    }
}
