<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\Config\Provider\PhpFileAlgorithmConfigurationProvider;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtPayload;
use PHPUnit\Framework\TestCase;
use Tests\Helpers\KeyProvider;

class TestCaseWithSecrets extends TestCase
{
    public array $publicKeys = [];
    public array $privateKeys = [];

    protected JwtKeyManager $manager;

    public function setUp(): void
    {
        $manager = new JwtKeyManager();

        $configArray = KeyProvider::getAll();

        foreach ($configArray as $algorithm => $options) {
            if (isset($options['private'])) {
                $manager->addPrivateKey($options['private'], $algorithm);
            }

            if (isset($options['public'])) {
                $manager->addPublicKey($options['public'], $algorithm);
            }

            if (isset($options['passphrase'])) {
                $manager->addPassphrase($options['passphrase'], $algorithm);
            }
        }

        $this->manager = $manager;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function jwsAlgorithmProvider(): array
    {
        return self::supportedAlgorithmsByType('JWS');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function jweAlgorithmProvider(): array
    {
        return self::supportedAlgorithmsByType('JWE');
    }

    /**
     * @return array<string, array{string}>
     */
    private static function supportedAlgorithmsByType(string $tokenType): array
    {
        $provider = new PhpFileAlgorithmConfigurationProvider();
        $algorithms = KeyProvider::getSupportedAlgorithms();

        $out = [];
        foreach ($algorithms as $algorithm) {
            $config = $provider->get($algorithm);
            if (($config['token_type'] ?? null) === $tokenType) {
                $out[$algorithm] = [$algorithm];
            }
        }

        return $out;
    }


    public static function supportedAlgorithmProvider(): array
    {
        return array_map(
            static fn (string $algorithm): array => [$algorithm],
            KeyProvider::getSupportedAlgorithms()
        );
    }

    protected function getPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuedAt('now')
            ->setExpiration('+1 minutes')
            ->setAudience('localhost');
    }
}
