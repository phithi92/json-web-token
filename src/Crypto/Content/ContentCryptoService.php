<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

abstract class ContentCryptoService implements PayloadHandlerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }
}
