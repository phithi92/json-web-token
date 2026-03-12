<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Service;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingJwtIdException;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Service\JwtClaimsValidationService;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
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

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsReturnsFalseWhenDefaultValidatorRejectsPayload(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user');
        $token = JwtBundleCodec::serialize($issuer->issue($algorithm, $payload));

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $defaultValidator = new JwtValidator(expectedIssuer: 'another-issuer');

        $service = new JwtClaimsValidationService($reader, $defaultValidator);

        $this->assertFalse($service->validateTokenClaims($token, $this->manager));
    }

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsPrefersProvidedValidatorOverDefault(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user');
        $token = JwtBundleCodec::serialize($issuer->issue($algorithm, $payload));

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $defaultValidator = new JwtValidator(expectedIssuer: 'another-issuer');
        $providedValidator = new JwtValidator(expectedIssuer: 'issuer');

        $service = new JwtClaimsValidationService($reader, $defaultValidator);

        $this->assertTrue($service->validateTokenClaims($token, $this->manager, $providedValidator));
    }


    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsReturnsFalseForExpiredPayload(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->setExpiration('-1 seconds')
            ->addClaim('sub', 'user');
        $token = JwtBundleCodec::serialize($issuer->issue($algorithm, $payload));

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $service = new JwtClaimsValidationService($reader, new JwtValidator(expectedIssuer: 'issuer'));

        $this->assertFalse($service->validateTokenClaims($token, $this->manager));
    }

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsThrowsWhenValidatorRequiresMissingJti(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user');
        $token = JwtBundleCodec::serialize($issuer->issue($algorithm, $payload));

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $validator = new JwtValidator(
            expectedIssuer: 'issuer',
            jwtIdValidator: new InMemoryJwtIdValidator()
        );
        $service = new JwtClaimsValidationService($reader, $validator);

        $this->expectException(MissingJwtIdException::class);
        $service->validateTokenClaims($token, $this->manager);
    }

    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsThrowsWhenTokenWasTampered(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user')
            ->addClaim('role', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $tamperedPayload = Base64UrlEncoder::encode(JsonEncoder::encode(['sub' => 'admin', 'role' => 'admin']));

        if ($bundle->getEncryption()->hasIv()) {
            [$header, $key, $iv, , $tag] = explode('.', $token);
            $token = implode('.', [$header, $key, $iv, $tamperedPayload, $tag]);
        } else {
            [$header, , $signature] = explode('.', $token);
            $token = implode('.', [$header, $tamperedPayload, $signature]);
        }

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());
        $service = new JwtClaimsValidationService($reader, new JwtValidator(expectedIssuer: 'issuer'));

        $this->expectException(InvalidTokenException::class);
        $service->validateTokenClaims($token, $this->manager);
    }
}
