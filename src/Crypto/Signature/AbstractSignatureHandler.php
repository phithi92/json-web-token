<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Config\AlgorithmConfig;
use Phithi92\JsonWebToken\Security\KeyManagement\DefaultKidResolver;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;

use function is_string;

abstract class AbstractSignatureHandler implements SignatureHandlerInterface
{
    protected JwtKeyManager $manager;

    protected KidResolverInterface $kidResolver;

    /**
     * @var array<string, AlgorithmConfig>
     */
    private array $cachedAlgorithmConfig = [];

    public function __construct(
        JwtKeyManager $manager,
        ?KidResolverInterface $kidResolver = null
    ) {
        $this->manager = $manager;
        $this->kidResolver = $kidResolver ?? new DefaultKidResolver();
    }

    protected function getAlgorithmConfig(array $config)
    {
        return $this->cachedAlgorithmConfig[$config] ??= new AlgorithmConfig($config);
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
