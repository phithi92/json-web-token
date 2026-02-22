<?php

declare(strict_types=1);

namespace Tests\phpunit\Crypto\Signature;

use Phithi92\JsonWebToken\Crypto\Signature\HmacSignatureHandler;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use PHPUnit\Framework\TestCase;

use function str_repeat;

final class HmacSignatureHandlerTest extends TestCase
{
    public function testComputeAndValidateSignatureForSha256(): void
    {
        $manager = new JwtKeyManager();
        $manager->addPassphrase(str_repeat('a', 32), 'hmac-key');

        $handler = new HmacSignatureHandler($manager);
        $signingInput = 'header.payload';

        $result = $handler->computeSignature('hmac-key', 'sha256', $signingInput);

        $handler->validateSignature('hmac-key', 'sha256', $signingInput, (string) $result->getSignature());

        $this->assertNotSame('', (string) $result->getSignature());
    }

    public function testValidateSignatureRejectsTamperedSignatureWithoutLeakingSigningInput(): void
    {
        $manager = new JwtKeyManager();
        $manager->addPassphrase(str_repeat('b', 32), 'hmac-key');

        $handler = new HmacSignatureHandler($manager);
        $aad = 'header.payload.with-sensitive-content';

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token: Signature is not valid');

        try {
            $handler->validateSignature('hmac-key', 'sha256', $aad, 'tampered-signature');
        } catch (InvalidTokenException $exception) {
            $this->assertStringNotContainsString($aad, $exception->getMessage());

            throw $exception;
        }
    }

    public function testComputeSignatureRejectsShortKeyWithoutLeakingSecret(): void
    {
        $secret = 'short-secret';
        $manager = new JwtKeyManager();
        $manager->addPassphrase($secret, 'hs512-key');

        $handler = new HmacSignatureHandler($manager);

        $this->expectException(InvalidTokenException::class);

        try {
            $handler->computeSignature('hs512-key', 'sha512', 'header.payload');
        } catch (InvalidTokenException $exception) {
            $this->assertStringContainsString('too short', $exception->getMessage());
            $this->assertStringNotContainsString($secret, $exception->getMessage());

            throw $exception;
        }
    }
}
