<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

abstract class SignatureService implements SignatureHandlerInterface
{
    protected JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }

    public function getSigningInput(EncryptedJwtBundle $bundle): string
    {
        return implode(
            '.',
            [
                Base64UrlEncoder::encode($bundle->getHeader()->toJson()),
                Base64UrlEncoder::encode($bundle->getPayload()->toJson()),
            ]
        );
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
        if ($bundle->getHeader()->hasKid()) {
            $kid = $bundle->getHeader()->getKid();
        } elseif (isset($config['name'])) {
            $kid = $config['name'];
        } else {
            throw new InvalidFormatException('No "kid" found in bundle or configuration');
        }

        return $kid;
    }
}
