<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

final class HandlerMethodResolver
{
    private const METHOD_MAP = [
        HandlerType::Signature->name => [
            HandlerOperation::Perform->name => 'computeSignature',
            HandlerOperation::Reverse->name => 'validateSignature',
        ],
        HandlerType::Cek->name => [
            HandlerOperation::Perform->name => 'initializeCek',
            HandlerOperation::Reverse->name => 'validateCek',
        ],
        HandlerType::Iv->name => [
            HandlerOperation::Perform->name => 'initializeIv',
            HandlerOperation::Reverse->name => 'validateIv',
        ],
        HandlerType::Key->name => [
            HandlerOperation::Perform->name => 'wrapKey',
            HandlerOperation::Reverse->name => 'unwrapKey',
        ],
        HandlerType::Payload->name => [
            HandlerOperation::Perform->name => 'encryptPayload',
            HandlerOperation::Reverse->name => 'decryptPayload',
        ],
    ];

    /**
     * Resolves the method name that should be called on a handler
     * based on its type and the operation direction.
     */
    public function resolve(HandlerType $type, HandlerOperation $operation): string
    {
        return self::METHOD_MAP[$type->name][$operation->name];
    }
}
