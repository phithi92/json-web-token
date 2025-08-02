<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

/**
 * Enum representing all supported handler types.
 *
 * Each type maps to a specific handler interface,
 * which is used as a key in the algorithm configuration.
 */
enum HandlerType
{
    case Signature;
    case Cek;
    case Iv;
    case Key;
    case Payload;

    public function interface(): string
    {
        return match ($this) {
            self::Signature => SignatureHandlerInterface::class,
            self::Cek => CekHandlerInterface::class,
            self::Iv => IvHandlerInterface::class,
            self::Key => KeyHandlerInterface::class,
            self::Payload => PayloadHandlerInterface::class,
        };
    }
}
