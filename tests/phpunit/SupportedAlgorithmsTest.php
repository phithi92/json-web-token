<?php

namespace Tests\phpunit;

use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Tests\Helpers\TokenStorage;
use Tests\Helpers\KeyProvider;
use Tests\phpunit\TestCaseWithSecrets;

class SupportedAlgorithmsTest extends TestCaseWithSecrets
{
    protected static array $supportedAlgorithms;

    public static function algorithmProvider(): array
    {
        // korrektes Format erzeugen:
        return self::$supportedAlgorithms = array_map(
            fn(string $alg): array => [$alg],
            KeyProvider::getSupportedAlgorithms()
        );
    }

    /**
     * @dataProvider algorithmProvider
     */
    public function testEncryptOnly(string $algorithm): void
    {
        $payload = self::getPayload();

        $token = JwtTokenFactory::createTokenString($algorithm, $this->manager, $payload);

        TokenStorage::write($algorithm, $token);

        $this->assertNotEmpty($token, "Token must not be empty for $algorithm");
    }

    /**
     * @dataProvider algorithmProvider
     */
    public function testDecryptOnly(string $algorithm): void
    {
        $token = TokenStorage::read($algorithm);

        $bundle = JwtTokenFactory::decryptToken($token, $this->manager);

        $this->assertInstanceOf(EncryptedJwtBundle::class, $bundle);
    }

    public static function tearDownAfterClass(): void
    {
        TokenStorage::cleanup();
    }
}
