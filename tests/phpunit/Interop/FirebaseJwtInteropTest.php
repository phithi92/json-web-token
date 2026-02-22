<?php

declare(strict_types=1);

namespace Tests\phpunit\Interop;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenServiceFactory;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Tests\Helpers\PemProvider;
use Tests\phpunit\TestCaseWithSecrets;
use Throwable;

final class FirebaseJwtInteropTest extends TestCaseWithSecrets
{
    private const ISSUER = 'interop.example';
    private const AUDIENCE = 'interop.example';

    private const BASE_CLAIMS = [
        'iss' => self::ISSUER,
        'aud' => self::AUDIENCE,
        'sub' => 'jws',
        'scope' => 'interop',
        // weit in der Zukunft (happy-path)
        'exp' => 4102444800,
    ];

    public function testFirebaseHs256TokenValidatesInLibrary(): void
    {
        $secret = PemProvider::getPassphrase('hmac/hs256');

        // firebase/php-jwt: 4th param is kid (key id), not alg
        // We omit kid so your library derives kid from alg ("HS256") per README.
        $token = JWT::encode(self::BASE_CLAIMS, $secret, 'HS256');

        $bundle = $this->service()->decryptToken(
            token: $token,
            manager: $this->manager,
            validator: $this->validator()
        );

        $payload = $bundle->getPayload();

        $this->assertSame(self::ISSUER, $payload->getClaim('iss'));
        $this->assertSame(self::AUDIENCE, $payload->getClaim('aud'));
        $this->assertSame('jws', $payload->getClaim('sub'));
        $this->assertSame('interop', $payload->getClaim('scope'));
        $this->assertSame(self::BASE_CLAIMS['exp'], $payload->getClaim('exp'));
    }

    public function testFirebaseRs256TokenValidatesInLibrary(): void
    {
        $privateKey = PemProvider::getPrivateKey('rsa/2048');

        // Omit kid so your library derives kid from alg ("RS256") per README.
        $token = JWT::encode(self::BASE_CLAIMS, $privateKey, 'RS256');

        $bundle = $this->service()->decryptToken(
            token: $token,
            manager: $this->manager,
            validator: $this->validator()
        );

        $payload = $bundle->getPayload();

        $this->assertSame(self::ISSUER, $payload->getClaim('iss'));
        $this->assertSame(self::AUDIENCE, $payload->getClaim('aud'));
        $this->assertSame('jws', $payload->getClaim('sub'));
        $this->assertSame('interop', $payload->getClaim('scope'));
        $this->assertSame(self::BASE_CLAIMS['exp'], $payload->getClaim('exp'));
    }

    public function testLibraryHs256TokenValidatesInFirebase(): void
    {
        $token = $this->service()->createTokenString(
            algorithm: 'HS256',
            manager: $this->manager,
            payload: $this->buildPayload(self::BASE_CLAIMS),
            validator: $this->validator(),
            // kid omitted => derived from algorithm ("HS256") per README
        );

        $secret = PemProvider::getPassphrase('hmac/hs256');
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));

        $this->assertSame(self::ISSUER, $decoded->iss ?? null);
        $this->assertSame(self::AUDIENCE, $decoded->aud ?? null);
        $this->assertSame('jws', $decoded->sub ?? null);
        $this->assertSame('interop', $decoded->scope ?? null);
        $this->assertSame(self::BASE_CLAIMS['exp'], $decoded->exp ?? null);
    }

    public function testLibraryRs256TokenValidatesInFirebase(): void
    {
        $token = $this->service()->createTokenString(
            algorithm: 'RS256',
            manager: $this->manager,
            payload: $this->buildPayload(self::BASE_CLAIMS),
            validator: $this->validator(),
            // kid omitted => derived from algorithm ("RS256") per README
        );

        $publicKey = PemProvider::getPublicKey('rsa/2048');
        $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

        $this->assertSame(self::ISSUER, $decoded->iss ?? null);
        $this->assertSame(self::AUDIENCE, $decoded->aud ?? null);
        $this->assertSame('jws', $decoded->sub ?? null);
        $this->assertSame('interop', $decoded->scope ?? null);
        $this->assertSame(self::BASE_CLAIMS['exp'], $decoded->exp ?? null);
    }

    public function testFirebaseAudArrayTokenValidatesInLibrary(): void
    {
        $secret = PemProvider::getPassphrase('hmac/hs256');

        $claims = self::BASE_CLAIMS;
        $claims['aud'] = [self::AUDIENCE, 'other-audience'];

        $token = JWT::encode($claims, $secret, 'HS256');

        $bundle = $this->service()->decryptToken(
            token: $token,
            manager: $this->manager,
            validator: $this->validator()
        );

        $this->assertSame($claims['aud'], $bundle->getPayload()->getClaim('aud'));
    }

    public function testLibraryUnicodeAndNestedClaimsValidateInFirebase(): void
    {
        $claims = self::BASE_CLAIMS;
        $claims['name'] = 'Jörg 🚀';
        $claims['ctx'] = ['roles' => ['admin', 'user'], 'meta' => ['n' => 123]];

        $token = $this->service()->createTokenString(
            algorithm: 'HS256',
            manager: $this->manager,
            payload: $this->buildPayload($claims),
            validator: $this->validator(),
        );

        $secret = PemProvider::getPassphrase('hmac/hs256');
        $decoded = JWT::decode($token, new Key($secret, 'HS256'));

        $this->assertSame($claims['name'], $decoded->name ?? null);
    }

    public function testExpiredFirebaseTokenIsRejectedByLibrary(): void
    {
        $secret = PemProvider::getPassphrase('hmac/hs256');

        $claims = self::BASE_CLAIMS;
        $claims['exp'] = 1; // garantiert abgelaufen

        $token = JWT::encode($claims, $secret, 'HS256');

        $this->expectException(Throwable::class);
        $this->service()->decryptToken(
            token: $token,
            manager: $this->manager,
            validator: $this->validator()
        );
    }

    public function testFirebaseTokenWithWrongIssuerIsRejectedByLibrary(): void
    {
        $secret = PemProvider::getPassphrase('hmac/hs256');

        $claims = self::BASE_CLAIMS;
        $claims['iss'] = 'wrong-issuer';

        $token = JWT::encode($claims, $secret, 'HS256');

        $this->expectException(Throwable::class);
        $this->service()->decryptToken(
            token: $token,
            manager: $this->manager,
            validator: $this->validator()
        );
    }

    private function service()
    {
        return JwtTokenServiceFactory::createDefault();
    }

    private function validator(): JwtValidator
    {
        return new JwtValidator(
            expectedIssuer: self::ISSUER,
            expectedAudience: self::AUDIENCE
        );
    }

    private function buildPayload(array $claims): JwtPayload
    {
        $payload = new JwtPayload();

        foreach ($claims as $k => $v) {
            $payload->setClaim((string) $k, $v);
        }

        return $payload;
    }
}
