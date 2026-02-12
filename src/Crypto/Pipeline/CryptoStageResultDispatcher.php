<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\ContentEncryption\ContentEncryptionResultHandler;
use Phithi92\JsonWebToken\Crypto\Iv\IvResultHandler;
use Phithi92\JsonWebToken\Crypto\Key\KeyResultHandler;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekResultHandler;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureResultHandler;
use Phithi92\JsonWebToken\Token\JwtBundle;

final class CryptoStageResultDispatcher
{
    /** @var array<string, CryptoStageResultHandlerInterface> */
    private array $stageHandlers;

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

    public function isSupported(AlgorithmInvocation $invocation): bool
    {
        if (!isset($this->stageHandlers[$invocation->target->name])) {
            return false;
        }

        return $this->stageHandlers[$invocation->target->name]->isSupported($invocation->operation);
    }
}
