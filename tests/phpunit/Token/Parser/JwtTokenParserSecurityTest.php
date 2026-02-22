<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Parser;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use PHPUnit\Framework\TestCase;

use function implode;

final class JwtTokenParserSecurityTest extends TestCase
{
    public function testMalformedTokenExceptionDoesNotLeakEncryptedKeyInputForDirTokens(): void
    {
        $sensitiveKeyMaterial = 'super-secret-encrypted-key';

        $header = ['alg' => 'dir', 'enc' => 'A256GCM'];
        $parts = [
            Base64UrlEncoder::encode(JsonEncoder::encode($header)),
            Base64UrlEncoder::encode($sensitiveKeyMaterial),
            Base64UrlEncoder::encode('iviviviviviv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('auth-tag'),
        ];

        try {
            JwtTokenParser::parse(implode('.', $parts));
            $this->fail('Expected MalformedTokenException to be thrown');
        } catch (MalformedTokenException $exception) {
            $this->assertStringNotContainsString($sensitiveKeyMaterial, $exception->getMessage());
            $this->assertStringContainsString(
                'encrypted key must be empty for "dir" algorithm.',
                $exception->getMessage()
            );
        }
    }
}
