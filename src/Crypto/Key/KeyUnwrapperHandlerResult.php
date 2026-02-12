<?php

namespace Phithi92\JsonWebToken\Crypto\Key;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;

final class KeyUnwrapperHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly string $contentEncryptionKey
    ) {
    }

    public function getContentEncryptionKey(): string
    {
        return $this->contentEncryptionKey;
    }
}
