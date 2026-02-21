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
/**
 * Enum representing the stages of cryptographic processing.
 *
 * Each stage corresponds to a specific step in handling encrypted content.
 */
enum CryptoProcessingStage
{
    /** Stage for handling digital signatures */
    case Signature;

    /** Stage for handling the Content Encryption Key (CEK) */
    case Cek;

    /** Stage for handling the Initialization Vector (IV) */
    case Iv;

    /** Stage for handling the encryption key */
    case Key;

    /** Stage for handling the actual encrypted payload */
    case Payload;

    /**
     * Returns the fully-qualified class name of the handler interface
     * associated with the current crypto processing stage.
     *
     * @return class-string The handler interface class for this stage
     */
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

    /**
     * Returns the processing priority of the stage.
     *
     * Lower numbers indicate higher priority in the processing order.
     *
     * @return int The priority of the stage
     */
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