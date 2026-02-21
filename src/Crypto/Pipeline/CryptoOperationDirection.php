<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

/**
 * Describes the direction of a cryptographic operation.
 *
 * This enum is used to distinguish between executing an operation (e.g. signing or encrypting)
 * and reversing it (e.g. verifying or decrypting).
 */
enum CryptoOperationDirection: string
{
    case Perform = 'perform';     // e.g. sign, encrypt, generate, transform
    case Reverse = 'reverse';     // e.g. verify, decrypt, extract, untransform
}
