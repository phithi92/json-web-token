<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\ContentEncryption;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;

final class DecryptionHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly string $plaintext
    ) {
    }

    public function getPlaintext(): string
    {
        return $this->plaintext;
    }
}
