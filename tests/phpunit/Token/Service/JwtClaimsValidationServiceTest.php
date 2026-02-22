<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Service;

use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Service\JwtClaimsValidationService;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtClaimsValidationServiceTest extends TestCaseWithSecrets
{
    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsUsesReaderAndValidator(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $validator = new JwtValidator(expectedIssuer: 'issuer');

        $service = new JwtClaimsValidationService($reader, $validator);

        $this->assertTrue($service->validateTokenClaims($token, $this->manager));
    }
}
