<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function implode;
use function is_string;

abstract class SignatureService implements SignatureHandlerInterface
{
    protected JwtKeyManager $manager;

    public function __construct(JwtKeyManager $manager)
    {
        $this->manager = $manager;
    }

    public function getSigningInput(JwtBundle $bundle): string
    {
        return implode(
            '.',
            [
                Base64UrlEncoder::encode(JwtHeaderJsonCodec::encodeStatic($bundle->getHeader())),
                Base64UrlEncoder::encode(JwtPayloadJsonCodec::encodeStatic($bundle->getPayload())),
            ]
        );
    }

    /**
     * Resolves the key ID (kid) from header or config.
     *
     * @param array<string, int|class-string<object>> $config
     *
     * @throws InvalidSignatureException
     */
    protected function resolveKid(JwtBundle $bundle, array $config): string
    {
        $kid = $bundle->getHeader()->getKid();

        if (! $bundle->getHeader()->hasKid()) {
            if ($this->existConfigKidFallback($config)) {
                $kid = (string) $config['name'];
            } else {
                throw new InvalidFormatException('No "kid" found in bundle or configuration');
            }
        }

        return $kid;
    }

    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    protected function getConfiguredHashAlgorithm(array $config): string
    {
        return is_string($config['hash_algorithm']) ? $config['hash_algorithm'] : '';
    }

    /**
     * @param array<string, int|class-string<object>> $config
     */
    private function existConfigKidFallback(array $config): bool
    {
        return isset($config['name']) && is_string($config['name']);
    }
}
