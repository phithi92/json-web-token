<?php

namespace Tests\phpunit;

use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Tests\Helpers\KeyProvider;
use Tests\Helpers\TokenStorage;

use function array_map;

class SupportedAlgorithmsTest extends TestCaseWithSecrets
{
    protected static array $supportedAlgorithms;

    public static function algorithmProvider(): array
    {
        // korrektes Format erzeugen:
        return self::$supportedAlgorithms = array_map(
            fn (string $alg): array => [$alg],
            KeyProvider::getSupportedAlgorithms()
        );
    }

    /**
     * @dataProvider algorithmProvider
     */
    public function testEncryptOnly(string $algorithm): void
    {
        $payload = self::getPayload();

        $service = new JwtTokenIssuer($this->manager);
        $bundle = $service->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        TokenStorage::write($algorithm, $token);

        $this->assertNotEmpty($token, "Token must not be empty for $algorithm");
    }

    /**
     * @dataProvider algorithmProvider
     */
    public function testDecryptOnly(string $algorithm): void
    {
        $token = TokenStorage::read($algorithm);

        $service = new JwtTokenDecryptor($this->manager);
        $bundle = $service->decrypt($token);

        $this->assertInstanceOf(JwtBundle::class, $bundle);
    }

    public static function tearDownAfterClass(): void
    {
        TokenStorage::cleanup();
    }
}
