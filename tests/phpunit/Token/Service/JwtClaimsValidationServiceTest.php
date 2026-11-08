<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Service;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingJwtIdException;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJtiValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtClaimsValidationServiceTest extends TestCaseWithSecrets
{
    /**
     * @dataProvider supportedAlgorithmProvider
     */
    public function testValidateTokenClaimsUsesDecryptorAndValidator(string $algorithm): void
    {
        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())
            ->setIssuer('issuer')
            ->addClaim('sub', 'user');
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $validator = new JwtValidator(expectedIssuer: 'issuer');
        $decryptor = new JwtTokenDecryptor($this->manager, $validator);

        $decryptedBundle = $decryptor->decrypt($token, $this->manager);

        $this->assertTrue($validator->isValid($decryptedBundle->getPayload()));
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
        $bundle = JwtBundleCodec::serialize($issuer->issue($algorithm, $payload));

        $defaultValidator = new JwtValidator(expectedIssuer: 'another-issuer');

        $decryptor = new JwtTokenDecryptor($this->manager, $defaultValidator);

        $decryptedBundle = $decryptor->decryptWithoutClaimValidation($bundle);

        $this->assertFalse($defaultValidator->isValid($decryptedBundle->getPayload()));
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

        $validator = new JwtValidator(expectedIssuer: 'issuer');

        $decryptor = new JwtTokenDecryptor($this->manager, $validator);

        $decryptedBundle = $decryptor->decryptWithoutClaimValidation($token);

        $this->assertFalse($validator->isValid($decryptedBundle->getPayload()));
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

        $validator = new JwtValidator(
            expectedIssuer: 'issuer',
            jwtIdValidator: new InMemoryJtiValidator()
        );

        $decryptor = new JwtTokenDecryptor($this->manager, $validator);

        $decryptedBundle = $decryptor->decryptWithoutClaimValidation($token);

        $this->expectException(MissingJwtIdException::class);
        $validator->assertValid($decryptedBundle->getPayload());
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

        $validator = new JwtValidator();

        $decryptor = new JwtTokenDecryptor($this->manager, $validator);

        $this->expectException(InvalidTokenException::class);
        $decryptedBundle = $decryptor->decryptWithoutClaimValidation($token);
    }
}
