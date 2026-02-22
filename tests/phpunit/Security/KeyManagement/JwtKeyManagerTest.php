<?php

declare(strict_types=1);

namespace Tests\phpunit\Security\KeyManagement;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyRole;
use PHPUnit\Framework\TestCase;
use Tests\Helpers\KeyProvider;

final class JwtKeyManagerTest extends TestCase
{
    public function testAddKeyPairAndMetadata(): void
    {
        $keys = KeyProvider::getKey('RS256');

        $privateKey = $keys['private'];
        $publicKey = $keys['public'];

        $manager = new JwtKeyManager();
        $manager->addKeyPair($privateKey, $publicKey, 'kid');

        $this->assertTrue($manager->hasKeyPair('kid'));
        $this->assertTrue($manager->hasKey('kid'));
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $manager->getPrivateKey('kid'));
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $manager->getPublicKey('kid'));

        $metadata = $manager->getKeyMetadata('kid', KeyRole::Private);
        $this->assertSame(KeyRole::Private, $metadata->role());
        $this->assertSame($privateKey, $metadata->pem());
    }

    public function testPassphraseStorage(): void
    {
        $manager = new JwtKeyManager();

        $manager->addPassphrase('secret', 'kid');

        $this->assertTrue($manager->hasPassphrase('kid'));
        $this->assertSame('secret', $manager->getPassphrase('kid'));
    }
}
