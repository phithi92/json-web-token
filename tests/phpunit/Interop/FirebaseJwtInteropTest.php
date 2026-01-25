<?php

declare(strict_types=1);

namespace Tests\phpunit\Interop;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Tests\Helpers\PemProvider;
use Tests\phpunit\TestCaseWithSecrets;

final class FirebaseJwtInteropTest extends TestCaseWithSecrets
{
    private const PAYLOAD = [
        'aud' => 'interop.example',
        'exp' => 4102444800,
        'iss' => 'interop.example',
        'scope' => 'interop',
        'sub' => 'jws',
    ];

    public function testFirebaseHs256TokenValidatesInLibrary(): void
    {
        $secret = PemProvider::getPassphrase('hmac/hs256');
        $token = JWT::encode(self::PAYLOAD, $secret, 'HS256', 'HS256');

        $decryptor = new JwtTokenDecryptor($this->manager);
        $bundle = $decryptor->decrypt($token);

        $payload = $bundle->getPayload();
        $this->assertSame(self::PAYLOAD['iss'], $payload->getClaim('iss'));
        $this->assertSame(self::PAYLOAD['aud'], $payload->getClaim('aud'));
        $this->assertSame(self::PAYLOAD['sub'], $payload->getClaim('sub'));
        $this->assertSame(self::PAYLOAD['scope'], $payload->getClaim('scope'));
        $this->assertSame(self::PAYLOAD['exp'], $payload->getClaim('exp'));
    }

    public function testFirebaseRs256TokenValidatesInLibrary(): void
    {
        $privateKey = PemProvider::getPrivateKey('rsa/2048');
        $token = JWT::encode(self::PAYLOAD, $privateKey, 'RS256', 'RS256');

        $decryptor = new JwtTokenDecryptor($this->manager);
        $bundle = $decryptor->decrypt($token);

        $payload = $bundle->getPayload();
        $this->assertSame(self::PAYLOAD['iss'], $payload->getClaim('iss'));
        $this->assertSame(self::PAYLOAD['aud'], $payload->getClaim('aud'));
        $this->assertSame(self::PAYLOAD['sub'], $payload->getClaim('sub'));
        $this->assertSame(self::PAYLOAD['scope'], $payload->getClaim('scope'));
        $this->assertSame(self::PAYLOAD['exp'], $payload->getClaim('exp'));
    }

    public function testLibraryHs256TokenValidatesInFirebase(): void
    {
        $payload = $this->buildPayload();
        $issuer = new JwtTokenIssuer($this->manager);
        $bundle = $issuer->issue('HS256', $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $secret = PemProvider::getPassphrase('hmac/hs256');
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));

        $this->assertSame(self::PAYLOAD['iss'], $decoded->iss ?? null);
        $this->assertSame(self::PAYLOAD['aud'], $decoded->aud ?? null);
        $this->assertSame(self::PAYLOAD['sub'], $decoded->sub ?? null);
        $this->assertSame(self::PAYLOAD['scope'], $decoded->scope ?? null);
        $this->assertSame(self::PAYLOAD['exp'], $decoded->exp ?? null);
    }

    public function testLibraryRs256TokenValidatesInFirebase(): void
    {
        $payload = $this->buildPayload();
        $issuer = new JwtTokenIssuer($this->manager);
        $bundle = $issuer->issue('RS256', $payload);
        $token = JwtBundleCodec::serialize($bundle);

        $publicKey = PemProvider::getPublicKey('rsa/2048');
        $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

        $this->assertSame(self::PAYLOAD['iss'], $decoded->iss ?? null);
        $this->assertSame(self::PAYLOAD['aud'], $decoded->aud ?? null);
        $this->assertSame(self::PAYLOAD['sub'], $decoded->sub ?? null);
        $this->assertSame(self::PAYLOAD['scope'], $decoded->scope ?? null);
        $this->assertSame(self::PAYLOAD['exp'], $decoded->exp ?? null);
    }

    private function buildPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setClaim('iss', self::PAYLOAD['iss'])
            ->setClaim('aud', self::PAYLOAD['aud'])
            ->setClaim('sub', self::PAYLOAD['sub'])
            ->setClaim('scope', self::PAYLOAD['scope'])
            ->setClaim('exp', self::PAYLOAD['exp']);
    }
}
