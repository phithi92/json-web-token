<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Interfaces\SignatureManagerInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

abstract class SignatureService implements SignatureManagerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }

    public function getSigningInput(EncryptedJwtBundle $bundle): string
    {
        return implode('.', [
            Base64UrlEncoder::encode($bundle->getHeader()->toJson()),
            Base64UrlEncoder::encode($bundle->getPayload()->toJson()),
        ]);
    }

    /**
     * Resolves the key ID (kid) from header or config.
     *
     * @param array<string, string> $config
     *
     * @throws InvalidSignatureException
     */
    protected function resolveKid(EncryptedJwtBundle $bundle, array $config): string
    {
        $kid = $bundle->getHeader()->getKid() ?? $config['name'] ?? null;

        if (! $kid) {
            throw new InvalidSignatureException('No key ID (kid) provided for signature operation.');
        }

        return $kid;
    }
}
