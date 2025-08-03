<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;

abstract class ContentCryptoService implements PayloadHandlerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }
}
