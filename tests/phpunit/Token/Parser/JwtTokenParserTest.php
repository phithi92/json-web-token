<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Parser;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use PHPUnit\Framework\TestCase;

use function implode;

final class JwtTokenParserTest extends TestCase
{
    public function testParseByTypeJwsToken(): void
    {
        $header = ['alg' => 'HS256', 'typ' => 'JWS'];
        $payload = ['sub' => 'user'];

        $parts = [
            Base64UrlEncoder::encode(JsonEncoder::encode($header)),
            Base64UrlEncoder::encode(JsonEncoder::encode($payload)),
            Base64UrlEncoder::encode('signature'),
        ];

        $bundle = JwtTokenParser::parse(implode('.', $parts));

        $this->assertSame('JWS', $bundle->getHeader()->getType());
        $this->assertSame('HS256', $bundle->getHeader()->getAlgorithm());
        $this->assertSame('user', $bundle->getPayload()->getClaim('sub'));
    }

    public function testParseByStructureJweTokenWithoutType(): void
    {
        $header = ['alg' => 'dir', 'enc' => 'A256GCM'];

        $parts = [
            Base64UrlEncoder::encode(JsonEncoder::encode($header)),
            '',
            Base64UrlEncoder::encode('iv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('tag'),
        ];

        $bundle = JwtTokenParser::parse(implode('.', $parts));

        $this->assertNull($bundle->getHeader()->getType());
        $this->assertSame('A256GCM', $bundle->getHeader()->getEnc());
    }

    public function testInvalidJwsStructureThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        $header = ['alg' => 'HS256', 'typ' => 'JWS'];
        $parts = [
            Base64UrlEncoder::encode(JsonEncoder::encode($header)),
            Base64UrlEncoder::encode('payload'),
            Base64UrlEncoder::encode('sig'),
            Base64UrlEncoder::encode('extra'),
        ];

        JwtTokenParser::parse(implode('.', $parts));
    }
}
