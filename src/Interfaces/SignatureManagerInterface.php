<?php

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\EncryptedJwtBundle;

interface SignatureManagerInterface
{
    /**
     *
     * @param   EncryptedJwtBundle $bundle
     * @param   array<string, string> $config
     * @return  void
     */
    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void;

    /**
     *
     * @param   EncryptedJwtBundle $bundle
     * @param   array<string, string> $config
     * @return  void
     */
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void;
}
