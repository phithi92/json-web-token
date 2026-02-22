<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Decryptor;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Tests\phpunit\TestCaseWithSecrets;

use function explode;
use function implode;
use function str_repeat;

final class JwtTokenDecryptorInvalidPartsTest extends TestCaseWithSecrets
{
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

        try {
            $decryptor->decrypt(implode('.', $parts));
            $this->fail('Expected InvalidTokenException to be thrown');
        } catch (InvalidTokenException $exception) {
            $this->assertStringNotContainsString('hacker', $exception->getMessage());
        }
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

        try {
            $decryptor->decrypt(implode('.', $parts));
            $this->fail('Expected InvalidTokenException to be thrown');
        } catch (InvalidTokenException $exception) {
            $this->assertStringNotContainsString('tampered-signature', $exception->getMessage());
        }
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
        $tamperedCiphertext = 'tampered-ciphertext';
        $parts[3] = Base64UrlEncoder::encode($tamperedCiphertext);

        $decryptor = new JwtTokenDecryptor($this->manager);

        try {
            $decryptor->decrypt(implode('.', $parts));
            $this->fail('Expected InvalidTokenException to be thrown');
        } catch (InvalidTokenException $exception) {
            $this->assertMatchesRegularExpression('/^Invalid token: Decrypt Payload Failed/', $exception->getMessage());
            $this->assertStringNotContainsString($tamperedCiphertext, $exception->getMessage());
        }
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

    /**
     * @dataProvider jweAlgorithmProvider
     */
    public function testJweDecryptErrorsDoNotLeakTokenOrClaimData(string $algorithm): void
    {
        $secretClaim = 'very-secret-user-data';

        $issuer = new JwtTokenIssuer($this->manager);
        $payload = (new JwtPayload())->addClaim('sub', $secretClaim);
        $bundle = $issuer->issue($algorithm, $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $parts = explode('.', $token);
        $parts[3] = Base64UrlEncoder::encode('tampered-ciphertext');

        $decryptor = new JwtTokenDecryptor($this->manager);

        try {
            $decryptor->decrypt(implode('.', $parts));
            $this->fail('Expected InvalidTokenException was not thrown.');
        } catch (InvalidTokenException $exception) {
            $message = $exception->getMessage();

            $this->assertStringNotContainsString($secretClaim, $message);
            $this->assertStringNotContainsString($token, $message);
            $this->assertStringContainsString('Invalid token:', $message);
        }
    }

    public function testMalformedTokenDoesNotEchoRawInputInExceptionMessage(): void
    {
        $rawSecret = 'raw-secret-fragment';
        $token = implode('.', [$rawSecret . '====', 'payload', 'signature']);

        $this->expectException(MalformedTokenException::class);
        $this->expectExceptionMessage('Malformed token: invalid Base64Url encoding.');

        try {
            JwtBundleCodec::parse($token);
        } catch (MalformedTokenException $exception) {
            $this->assertStringNotContainsString($rawSecret, $exception->getMessage());
            throw $exception;
        }
    }

}
