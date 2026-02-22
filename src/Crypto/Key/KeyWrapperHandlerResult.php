<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;

final class KeyWrapperHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly string $wrappedKey
    ) {
    }

    public function getWrappedKey(): string
    {
        return $this->wrappedKey;
    }
}
