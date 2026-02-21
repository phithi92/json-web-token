<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\ContentEncryption\ContentEncryptionResultHandler;
use Phithi92\JsonWebToken\Crypto\Iv\IvResultHandler;
use Phithi92\JsonWebToken\Crypto\Key\KeyResultHandler;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekResultHandler;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureResultHandler;
use Phithi92\JsonWebToken\Token\JwtBundle;

/**
 * Dispatches crypto stage results to dedicated stage handlers.
 *
 * This dispatcher routes an algorithm invocation (target stage and operation direction)
 * to the corresponding stage result handler. Each handler applies a stage-specific result
 * to a JWT bundle and returns the updated bundle.
 *
 * Handlers are selected by the processing stage name. Custom handlers can be injected to
 * override the defaults; any missing stages are filled with built-in handlers. Call
 * isSupported() before process() to ensure that a handler exists and supports the requested
 * operation.
 */
final class CryptoStageResultDispatcher
{
    /** @var array<string, CryptoStageResultHandlerInterface> */
    private array $stageHandlers;

    /**
     * Initializes the dispatcher with a map of stage-specific result handlers.
     *
     * Custom handlers can be provided to override the defaults. The keys must match
     * the stage name (e.g. CryptoProcessingStage::Signature->name). Any missing
     * stages are filled with built-in default handlers.
     *
     * @param array<string, CryptoStageResultHandlerInterface> $stageHandlers
     *     Optional stage-to-handler map. Provided handlers take precedence over defaults.
     */
    public function __construct(array $stageHandlers = [])
    {
        $this->stageHandlers = $stageHandlers + [
            CryptoProcessingStage::Signature->name => new SignatureResultHandler(),
            CryptoProcessingStage::Cek->name => new CekResultHandler(),
            CryptoProcessingStage::Iv->name => new IvResultHandler(),
            CryptoProcessingStage::Key->name => new KeyResultHandler(),
            CryptoProcessingStage::Payload->name => new ContentEncryptionResultHandler(),
        ];
    }

    /**
     * Dispatches a crypto stage result to the handler that is responsible for the invocation target.
     *
     * The handler is selected by the invocation target stage and will apply the given result to the
     * provided bundle according to the invocation operation (perform vs. reverse). The returned
     * bundle is the updated instance as produced by the handler.
     *
     * Note: This method expects the target stage to be configured. Use isSupported() to check
     * availability before calling process(), otherwise an undefined index error may occur.
     *
     * @param AlgorithmInvocation $invocation Describes target stage and operation direction.
     * @param JwtBundle $bundle The current JWT bundle to be updated by the handler.
     * @param CryptoStageResultInterface $result The stage computation result to apply.
     *
     * @return JwtBundle The updated bundle after the stage result has been processed.
     */
    public function process(
        AlgorithmInvocation $invocation,
        JwtBundle $bundle,
        CryptoStageResultInterface $result,
    ): JwtBundle {
        $handler = $this->stageHandlers[$invocation->target->name];

        return $handler->handle(
            operation: $invocation->operation,
            result: $result,
            bundle: $bundle,
        );
    }

    /**
     * Checks whether this dispatcher can process the given invocation.
     *
     * Returns true only if a handler is registered for the invocation target stage and
     * that handler supports the requested operation direction.
     *
     * @param AlgorithmInvocation $invocation The invocation to validate (stage + operation).
     *
     * @return bool True if the invocation can be dispatched; otherwise false.
     */
    public function isSupported(AlgorithmInvocation $invocation): bool
    {
        if (! isset($this->stageHandlers[$invocation->target->name])) {
            return false;
        }

        return $this->stageHandlers[$invocation->target->name]->isSupported($invocation->operation);
    }
}
