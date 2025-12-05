<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Token\JwtPayload;
use PHPUnit\Framework\TestCase;
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

    protected function getPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuedAt('now')
            ->setExpiration('+1 minutes')
            ->setAudience('localhost');
    }
}
