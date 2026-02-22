<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface CryptoStageResultHandlerInterface
{
    /**
     * Determines whether this implementation supports a result handler for the given
     * crypto operation direction.
     *
     * Use this method to decide at runtime if the handler can be applied for the
     * provided {@see CryptoOperationDirection}.
     *
     * @param CryptoOperationDirection $direction The crypto operation direction (e.g. inbound/outbound).
     *
     * @return bool True if the result handler is supported for the given direction; otherwise false.
     */
    public function isSupported(CryptoOperationDirection $direction): bool;

    public function handle(
        CryptoOperationDirection $operation,
        CryptoStageResultInterface $result,
        JwtBundle $bundle,
    ): JwtBundle;
}
