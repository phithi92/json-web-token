<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Reader;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtTokenReaderTest extends TestCaseWithSecrets
{
    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testDecryptTokenUsesFactoryAndValidator(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $result = $reader->decryptToken($token, $this->manager);

        $this->assertSame('user', $result->getPayload()->getClaim('sub'));
    }

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testDecryptTokenWithoutClaimValidationUsesFactory(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $result = $reader->decryptTokenWithoutClaimValidation($token, $this->manager);

        $this->assertSame('user', $result->getPayload()->getClaim('sub'));
    }

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testDecryptTokenRejectsPayloadTamperingAttack(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user')->addClaim('role', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $tamperedPayload = Base64UrlEncoder::encode(JsonEncoder::encode(['sub' => 'admin', 'role' => 'admin']));

        if ($bundle->getEncryption()->hasIv()) {
            [$header, $key, $iv, ,$tag] = explode('.', $token);
            $tamperedToken = implode('.', [$header, $key, $iv, $tamperedPayload, $tag]);
        } else {
            [$header, , $signature] = explode('.', $token);
            $tamperedToken = implode('.', [$header, $tamperedPayload, $signature]);
        }

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $this->expectException(InvalidTokenException::class);
        $reader->decryptToken($tamperedToken, $this->manager);
    }
}
