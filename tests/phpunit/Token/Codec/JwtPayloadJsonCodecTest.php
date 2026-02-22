<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtPayload;
use PHPUnit\Framework\TestCase;

final class JwtPayloadJsonCodecTest extends TestCase
{
    public function testEncodeReturnsJsonForPayload(): void
    {
        $jsonCodec = new JwtPayloadJsonCodec();

        $payloadCodec = new JwtPayloadCodec();
        $payload = $payloadCodec->decode([
            'sub' => '1234567890',
            'name' => 'John Doe',
            'admin' => true,
            'iat' => 1516239022,
        ]);

        $json = $jsonCodec->encode($payload);

        self::assertJson($json);

        /** @var array<string,mixed> $decoded */
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        self::assertSame($payload->toArray(), $decoded);
    }

    public function testDecodeHydratesNewPayload(): void
    {
        $codec = new JwtPayloadJsonCodec();

        $data = [
            'sub' => '123',
            'roles' => ['user', 'admin'],
            'exp' => 1700000000,
        ];

        $json = json_encode($data, JSON_THROW_ON_ERROR);

        $payload = $codec->decode($json);

        self::assertInstanceOf(JwtPayload::class, $payload);
        self::assertSame($data, $payload->toArray());
    }

    public function testDecodeThrowsMalformedTokenExceptionOnInvalidJson(): void
    {
        $codec = new JwtPayloadJsonCodec();

        $this->expectException(MalformedTokenException::class);
        $this->expectExceptionMessage('Token payload is not valid JSON');

        $codec->decode('{"sub": "123",'); // invalid JSON
    }

    public function testDecodeIntoPopulatesTargetInstance(): void
    {
        $codec = new JwtPayloadJsonCodec();

        $json = json_encode(['foo' => 'bar', 'n' => 1], JSON_THROW_ON_ERROR);

        $payloadCodec = new JwtPayloadCodec();
        $target = $payloadCodec->decode(['foo' => 'old', 'keep' => 'value']);

        $codec->decodeInto($json, $target);

        // Erwartung: Zielinstanz wurde mit JSON-Daten befüllt.
        // (Ob "keep" erhalten bleibt oder überschrieben wird, hängt von JwtPayloadCodec::decode ab.
        // Hier testen wir minimal, dass die JSON-Werte danach vorhanden sind.)
        $arr = $target->toArray();
        self::assertSame('bar', $arr['foo'] ?? null);
        self::assertSame(1, $arr['n'] ?? null);
    }

    public function testEncodeStaticDelegatesToInstance(): void
    {
        $p = new JwtPayloadCodec();
        $payload = $p->decode(['a' => 1]);

        $json = JwtPayloadJsonCodec::encodeStatic($payload);

        self::assertJson($json);

        /** @var array<string,mixed> $decoded */
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['a' => 1], $decoded);
    }

    public function testDecodeStaticReturnsPayload(): void
    {
        $json = json_encode(['a' => 1, 'b' => true], JSON_THROW_ON_ERROR);

        $payload = JwtPayloadJsonCodec::decodeStatic($json);

        self::assertInstanceOf(JwtPayload::class, $payload);
        self::assertSame(['a' => 1, 'b' => true], $payload->toArray());
    }

    public function testDecodeStaticIntoPopulatesProvidedPayload(): void
    {
        $json = json_encode(['x' => 'y'], JSON_THROW_ON_ERROR);

        $payloadCodec = new JwtPayloadCodec();
        $target = $payloadCodec->decode([]);

        JwtPayloadJsonCodec::decodeStaticInto($json, $target);

        self::assertSame(['x' => 'y'], $target->toArray());
    }

    public function testDecodeRespectsCustomDepthForDeepJson(): void
    {
        $codec = new JwtPayloadJsonCodec();

        $deep = ['a' => ['b' => ['c' => ['d' => ['e' => ['f' => 'g']]]]]]; // depth > 6 je nach Zählweise

        $json = json_encode($deep, JSON_THROW_ON_ERROR);

        // Wenn der Depth zu klein ist, sollte decodeJson i.d.R. fehlschlagen -> MalformedTokenException
        $this->expectException(MalformedTokenException::class);
        $this->expectExceptionMessage('Token payload is not valid JSON');

        $codec->decode($json, 2);
    }
}
