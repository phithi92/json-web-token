<?php

declare(strict_types=1);

namespace Tests;

require_once __DIR__ . '/../Helpers/KeyProvider.php';

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenParser;
use Phithi92\JsonWebToken\Security\PassphraseStore;
use Phithi92\JsonWebToken\Security\KeyStore;
use Tests\Helpers\KeyProvider;

class TestCaseWithSecrets extends TestCase
{
    public array $publicKeys = [];
    public array $privateKeys = [];

    protected JwtAlgorithmManager $manager;

    public function setUp(): void
    {
        $manager = new JwtAlgorithmManager();

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


    public function createToken(
        string $algorithm
    ): string {
        $payload = $this->getPayload();

        $bundle = JwtTokenFactory::createToken($this->manager, $payload, $algorithm);

        $decryptedToken = JwtTokenParser::serialize($bundle);

        $this->assertIsString($decryptedToken, 'Token sollte ein String sein');
        return $decryptedToken;
    }

    public function decryptToken(
        string $token,
        JwtAlgorithmManager $manager = null
    ) {
        $resolvedManager = $manager ?? $this->manager;

        $decryptedToken = JwtTokenFactory::decryptToken($resolvedManager, $token);

        $this->assertInstanceOf(EncryptedJwtBundle::class, $decryptedToken);
    }

    protected function getPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuedAt('now')
            ->setExpiration('+1 minutes')
            ->setAudience('localhost');
    }
}
