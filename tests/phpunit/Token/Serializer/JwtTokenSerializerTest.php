<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Serializer;

use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Token\Serializer\JwtTokenSerializer;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use PHPUnit\Framework\TestCase;

use function explode;

final class JwtTokenSerializerTest extends TestCase
{
    public function testSerializeJweWithDirectAlgorithmOmitsEncryptedKey(): void
    {
        $header = (new JwtHeader())
            ->setType('JWE')
            ->setAlgorithm('dir')
            ->setEnc('A256GCM');

        $bundle = new JwtBundle($header, new JwtPayload());
        $bundle->setEncryption(new JwtEncryptionData(
            aad: 'aad',
            iv: 'iv',
            authTag: 'tag'
        ));
        $bundle->getPayload()->setEncryptedPayload('ciphertext');

        $token = JwtTokenSerializer::serialize($bundle);

        $parts = explode('.', $token);
        $this->assertCount(5, $parts);
        $this->assertSame('', Base64UrlEncoder::decode($parts[1]));
    }

    public function testSerializeJwsToken(): void
    {
        $header = (new JwtHeader())
            ->setType('JWS')
            ->setAlgorithm('HS256');

        $payload = (new JwtPayload())->addClaim('sub', 'user');

        $bundle = new JwtBundle($header, $payload);
        $bundle->setSignature(new JwtSignature('signature'));

        $token = JwtTokenSerializer::serialize($bundle);

        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
    }
}
