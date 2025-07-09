<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Encryption;

use Phithi92\JsonWebToken\Interfaces\KeyManagementManagerInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

/**
 * Base class for key cryptographic operations using JWT algorithms.
 */
abstract class KeyCryptoService implements KeyManagementManagerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }
}
