<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface CryptoStageResultHandlerInterface
{
    public function isSupported(CryptoOperationDirection $direction): bool;

    public function handle(
        CryptoOperationDirection $operation,
        CryptoStageResultInterface $result,
        JwtBundle $bundle,
    ): JwtBundle;
}
