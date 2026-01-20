<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Issuer;

use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenIssuerFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtTokenReissuerTest extends TestCaseWithSecrets
{
    public function testReissueBundleFiltersTimeClaims(): void
    {
        $payload = (new JwtPayload())
            ->setIssuedAt('now')
            ->setNotBefore('now')
            ->setExpiration('+2 minutes')
            ->addClaim('auth_time', time())
            ->addClaim('sub', 'user');

        $issuer = new JwtTokenIssuer($this->manager);
        $bundle = $issuer->issue('A256GCM', $payload);

        $reissuer = new JwtTokenReissuer(
            new JwtPayloadCodec(),
            new JwtValidator(),
            new JwtTokenIssuerFactory()
        );

        $reissued = $reissuer->reissueBundle('+1 minutes', $bundle, $this->manager);

        $reissuedPayload = $reissued->getPayload();

        $this->assertSame('user', $reissuedPayload->getClaim('sub'));
        $this->assertNull($reissuedPayload->getIssuedAt());
        $this->assertNull($reissuedPayload->getNotBefore());
        $this->assertNull($reissuedPayload->getClaim('auth_time'));
        $this->assertNotNull($reissuedPayload->getExpiration());
    }
}
