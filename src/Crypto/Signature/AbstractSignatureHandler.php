<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Security\KeyManagement\DefaultKidResolver;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function implode;
use function is_string;

abstract class AbstractSignatureHandler implements SignatureHandlerInterface
{
    protected JwtKeyManager $manager;

    protected KidResolverInterface $kidResolver;

    public function __construct(
        JwtKeyManager $manager,
        ?KidResolverInterface $kidResolver = null
    ) {
        $this->manager = $manager;
        $this->kidResolver = $kidResolver ?? new DefaultKidResolver($this->manager);
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
     * @param array<string,string|int|class-string<object>> $config
     */
    protected function getConfiguredHashAlgorithm(array $config): string
    {
        return (isset($config['hash_algorithm']) && is_string($config['hash_algorithm']))
            ? $config['hash_algorithm']
            : '';
    }
}
