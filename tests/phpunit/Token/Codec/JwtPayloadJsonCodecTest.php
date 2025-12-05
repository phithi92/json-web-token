<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtPayload;
use PHPUnit\Framework\TestCase;

class JwtPayloadJsonCodecTest extends TestCase
{
    public function testEncodeProducesString(): void
    {
        $payload = new JwtPayload();
        $payload->fromArray(['sub' => '1234567890']);

        $codec = new JwtPayloadJsonCodec();
        $result = $codec->encode($payload);

        $this->assertIsString($result);
    }

    public function testDecodeReturnsPayload(): void
    {
        $json = '{"sub":"abc"}';
        $codec = new JwtPayloadJsonCodec();

        $payload = $codec->decode($json);

        $this->assertInstanceOf(JwtPayload::class, $payload);
        $this->assertSame('abc', $payload->getClaim('sub'));
    }

    public function testDecodeIntoModifiesTargetPayload(): void
    {
        $json = '{"role":"user"}';
        $payload = new JwtPayload();

        $codec = new JwtPayloadJsonCodec();
        $codec->decodeInto($json, $payload);

        $this->assertSame('user', $payload->getClaim('role'));
    }

    public function testDecodeThrowsOnInvalidJson(): void
    {
        $this->expectException(MalformedTokenException::class);
        $this->expectExceptionMessage('Token payload is not valid JSON');

        $codec = new JwtPayloadJsonCodec();
        $codec->decode('{invalid');
    }

    public function testEncodeStaticProducesString(): void
    {
        $payload = new JwtPayload();
        $payload->fromArray(['key' => 'val']);

        $result = JwtPayloadJsonCodec::encodeStatic($payload);

        $this->assertIsString($result);
    }

    public function testDecodeStaticReturnsPayload(): void
    {
        $payload = JwtPayloadJsonCodec::decodeStatic('{"exp":123}');

        $this->assertInstanceOf(JwtPayload::class, $payload);
        $this->assertSame(123, $payload->getClaim('exp'));
    }

    public function testDecodeStaticIntoWorks(): void
    {
        $json = '{"foo":"bar"}';
        $payload = new JwtPayload();

        JwtPayloadJsonCodec::decodeStaticInto($json, $payload);

        $this->assertSame('bar', $payload->getClaim('foo'));
    }

    public function testStaticInstanceCacheBehavior(): void
    {
        $payload = new JwtPayload();
        $payload->fromArray(['cached' => true]);

        $first = JwtPayloadJsonCodec::encodeStatic($payload, 2);
        $second = JwtPayloadJsonCodec::encodeStatic($payload, 2);

        $this->assertSame($first, $second);
    }
}
