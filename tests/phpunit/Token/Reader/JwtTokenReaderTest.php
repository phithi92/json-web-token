<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Reader;

use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtTokenReaderTest extends TestCaseWithSecrets
{
    public function testDecryptTokenUsesFactoryAndValidator(): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue('HS256', $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $result = $reader->decryptToken($token, $this->manager);

        $this->assertSame('user', $result->getPayload()->getClaim('sub'));
    }

    public function testDecryptTokenWithoutClaimValidationUsesFactory(): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', 'user');
        $bundle = $issuer->issue('HS256', $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $result = $reader->decryptTokenWithoutClaimValidation($token, $this->manager);

        $this->assertSame('user', $result->getPayload()->getClaim('sub'));
    }
}
