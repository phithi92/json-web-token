<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Decryptor;

use Phithi92\JsonWebToken\Config\Provider\PhpFileAlgorithmConfigurationProvider;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Tests\Helpers\KeyProvider;
use Tests\phpunit\TestCaseWithSecrets;

use function explode;
use function implode;
use function str_repeat;

final class JwtTokenDecryptorInvalidPartsTest extends TestCaseWithSecrets
{
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

    /**
     * @dataProvider jwsAlgorithmProvider
     */
    public function testJwsTamperedPayloadThrowsInvalidSignature(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);
        $parts[1] = Base64UrlEncoder::encode(JsonEncoder::encode(['sub' => 'hacker']));

        $decryptor = new JwtTokenDecryptor($this->manager);

        $this->expectException(InvalidTokenException::class);
        $decryptor->decrypt(implode('.', $parts));
    }

    /**
     * @dataProvider jwsAlgorithmProvider
     */
    public function testJwsTamperedSignatureThrowsInvalidSignature(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);
        $parts[2] = Base64UrlEncoder::encode('tampered-signature');

        $decryptor = new JwtTokenDecryptor($this->manager);

        $this->expectException(InvalidTokenException::class);
        $decryptor->decrypt(implode('.', $parts));
    }

    /**
     * @dataProvider jweAlgorithmProvider
     */
    public function testJweTamperedIvThrowsInvalidToken(string $algorithm): void
    {
        $msg = 'Invalid token: Initialization vector length mismatch (got 3 bytes, expected 12).';

        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);

        $parts[2] = Base64UrlEncoder::encode('ass');

        $decryptor = new JwtTokenDecryptor($this->manager);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage($msg);
        $decryptor->decrypt(implode('.', $parts));
    }

    /**
     * @dataProvider jweAlgorithmProvider
     */
    public function testJweTamperedCiphertextThrowsInvalidToken(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);
        $parts[3] = Base64UrlEncoder::encode('tampered-ciphertext');

        $decryptor = new JwtTokenDecryptor($this->manager);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageMatches('/^Invalid token: Decrypt Payload Failed/');

        $decryptor->decrypt(implode('.', $parts));
    }

    /**
     * @dataProvider jweAlgorithmProvider
     */
    public function testJweTamperedAuthTagThrowsInvalidToken(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);
        $parts[4] = Base64UrlEncoder::encode(str_repeat('a', 16));

        $decryptor = new JwtTokenDecryptor($this->manager);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageMatches('/^Invalid token: Decrypt Payload Failed/');

        $decryptor->decrypt(implode('.', $parts));
    }
}
