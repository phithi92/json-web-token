<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\ContentEncryption\ContentEncryptionHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Iv\IvHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Key\KeyHandlerInterface;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;

/**
 * Enum representing all supported handler types.
 *
 * Each type maps to a specific handler interface,
 * which is used as a key in the algorithm configuration.
 */
enum CryptoProcessingStage
{
    case Signature;
    case Cek;
    case Iv;
    case Key;
    case Payload;

    public function interfaceClass(): string
    {
        return match ($this) {
            self::Signature => SignatureHandlerInterface::class,
            self::Cek => CekHandlerInterface::class,
            self::Iv => IvHandlerInterface::class,
            self::Key => KeyHandlerInterface::class,
            self::Payload => ContentEncryptionHandlerInterface::class,
        };
    }

    public function priority(): int
    {
        return match ($this) {
            self::Cek => 1,
            self::Key => 2,
            self::Iv => 3,
            self::Payload => 4,
            self::Signature => 5,
        };
    }
}
