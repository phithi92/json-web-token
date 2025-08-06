<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

use Phithi92\JsonWebToken\Exceptions\Handler\UnsupportedHandlerMethodException;

final class HandlerMethodResolver
{
    /**
     * Resolves the method name that should be called on a handler
     * based on its type and the operation direction.
     */
    public function resolve(HandlerType $type, HandlerOperation $operation): string
    {
        return match (true) {
            $type === HandlerType::Signature && $operation === HandlerOperation::Perform => 'computeSignature',
            $type === HandlerType::Signature && $operation === HandlerOperation::Reverse => 'validateSignature',

            $type === HandlerType::Cek && $operation === HandlerOperation::Perform => 'initializeCek',
            $type === HandlerType::Cek && $operation === HandlerOperation::Reverse => 'validateCek',

            $type === HandlerType::Iv && $operation === HandlerOperation::Perform => 'initializeIv',
            $type === HandlerType::Iv && $operation === HandlerOperation::Reverse => 'validateIv',

            $type === HandlerType::Key && $operation === HandlerOperation::Perform => 'wrapKey',
            $type === HandlerType::Key && $operation === HandlerOperation::Reverse => 'unwrapKey',

            $type === HandlerType::Payload && $operation === HandlerOperation::Perform => 'encryptPayload',
            $type === HandlerType::Payload && $operation === HandlerOperation::Reverse => 'decryptPayload',

            default => throw new UnsupportedHandlerMethodException(),
        };
    }
}
