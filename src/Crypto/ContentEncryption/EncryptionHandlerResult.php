<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\ContentEncryption;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultInterface;

/**
 * Result payload for content encryption operations.
 *
 * Contains the ciphertext and authentication tag returned by content encryption handlers.
 */
final class EncryptionHandlerResult implements CryptoStageResultInterface
{
    public function __construct(
        private readonly string $ciphertext,
        private readonly string $authenticationTag,
    ) {
    }

    public function getCiphertext(): string
    {
        return $this->ciphertext;
    }

    public function getAuthenticationTag(): string
    {
        return $this->authenticationTag;
    }
}
