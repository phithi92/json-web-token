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
    public function supports(AlgorithmInvocation $invokation): bool
    {
        return isset(self::METHOD_MAP[$invokation->target->name][$invokation->operation->name]);
    }

    /**
     * Resolves the handler method name for the given processing stage and operation direction.
     *
     * This method returns the method identifier as defined in the internal method map.
     * It assumes the combination is supported; call supports() beforehand to avoid
     * an undefined index error.
     *
     * @return string The handler method name to invoke (e.g. "encryptPayload", "decryptPayload").
     */
    public function resolve(AlgorithmInvocation $invokation): string
    {
        return self::METHOD_MAP[$invokation->target->name][$invokation->operation->name];
    }
}
