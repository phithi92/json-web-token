<?php

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Interfaces\ContentEncryptionManagerInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

abstract class ContentCryptoService implements ContentEncryptionManagerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }
}
