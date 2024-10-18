<?php

use Phithi92\JsonWebToken\JsonWebToken;
use Phithi92\JsonWebToken\PayloadBuilder;
use Phithi92\JsonWebToken\Security\Openssl;
use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;

require_once __DIR__ . '/TestCaseWithSecrets.php';

class JsonWebTokenTest extends TestCaseWithSecrets
{
    
    private JsonWebToken $JsonWebToken;
    private PayloadBuilder $Jwt;
    private Openssl $cipher;
    
    
    public function setUp(): void
    {
        parent::setUp();
        
        // Initialize the cipher and JsonWebToken in the setup for reuse
        $this->Jwt = (new PayloadBuilder())
            ->setExpiration('+15min')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local')
            ->addField('random', bin2hex(random_bytes(16)));

        $this->cipher = (new Openssl())
            ->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $this->JsonWebToken = new JsonWebToken($this->cipher);
    }

    /**
     * Test to validate behavior with malformed or tampered tokens.
     */
    public function testMalformedToken()
    {
        $malformedToken = 'invalid.token.structure';

        $this->expectException(InvalidTokenException::class);
        $this->JsonWebToken->validateToken($malformedToken, $this->publicKey2048);
    }

    /**
     * Test to ensure token validation fails with an incorrect key.
     */
    public function testValidationWithIncorrectKey()
    {
        $wrongKey = 'incorrectSecret';

        $token = $this->JsonWebToken->create($this->Jwt, $this->secret64, 'JWS', 'HS256');
        $this->assertIsString($token);

        // Now validate with the wrong key
        $this->expectException(InvalidArgumentException::class);
        $this->JsonWebToken->validateToken($token, $wrongKey);
    }

    /**
     * Test to ensure that invalid algorithms throw an exception.
     */
    public function testUnsupportedAlgorithm()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->JsonWebToken->create($this->Jwt, $this->secret64, 'JWS', 'UNSUPPORTED_ALGO');
    }

    /**
     * Test to validate behavior when the payload is empty.
     */
    public function testEmptyPayload()
    {
        $emptyJwt = new PayloadBuilder(); // Empty payload

        $this->expectException(InvalidArgumentException::class);
        $this->JsonWebToken->create($emptyJwt, $this->secret64, 'JWS', 'HS256');
    }

    /**
     * Test expired token validation should fail.
     */
    public function testExpiredToken()
    {
        $expiredJwt = (new PayloadBuilder())
            ->setExpiration('-1 hour')  // Expiration time in the past
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local');

        $token = $this->JsonWebToken->create($expiredJwt, $this->secret64, 'JWS', 'HS256');

        $this->assertIsString($token);

        // Expect token validation to fail due to expiration
        $this->expectException(InvalidTokenException::class);
        $this->JsonWebToken->validateToken($token, $this->secret64);
    }

    /**
     * Test token creation with invalid key length for symmetric algorithms.
     */
    public function testInvalidKeyLength()
    {
        $shortKey = 'short';

        $this->expectException(InvalidArgumentException::class);
        $this->JsonWebToken->create($this->Jwt, $shortKey, 'JWS', 'HS256');
    }

    /**
     * Test validation for a token issued in the future (iat claim).
     */
    public function testTokenIssuedInFuture()
    {
        $futureJwt = (new PayloadBuilder())
            ->setIssuedAt('+1 hour') // Issued one hour in the future
            ->setExpiration('+2 hours')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local');

        $token = $this->JsonWebToken->create($futureJwt, $this->secret64, 'JWS', 'HS256');

        $this->assertIsString($token);

        // Expect validation to fail as the token is not valid yet
        $this->expectException(InvalidTokenException::class);
        $this->JsonWebToken->validateToken($token, $this->secret64);
    }

    /**
     * Test tampered token should fail validation.
     */
    public function testTamperedToken()
    {
        $token = $this->JsonWebToken->create($this->Jwt, $this->secret64, 'JWS', 'HS256');

        $this->assertIsString($token);

        // Tamper with the token by altering the payload
        $tamperedToken = str_replace('.', 'tampered.', $token);

        // Expect validation to fail due to tampering
        $this->expectException(InvalidTokenException::class);
        $this->JsonWebToken->validateToken($tamperedToken, $this->secret64);
    }
}
