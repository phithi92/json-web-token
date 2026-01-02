<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;

/**
 * Base class for key cryptographic operations using JWT algorithms.
 */
abstract class KeyCryptoService implements KeyHandlerInterface
{
    protected JwtKeyManager $manager;

    public function __construct(JwtKeyManager $manager)
    {
        $this->manager = $manager;
    }
}
