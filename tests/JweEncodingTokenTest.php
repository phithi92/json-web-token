<?php

use Phithi92\JsonWebToken\JsonWebToken;
use Phithi92\JsonWebToken\PayloadBuilder;
use Phithi92\JsonWebToken\Security\Openssl;
use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;

require_once __DIR__ . '/TestCaseWithSecrets.php';

class JweEncodingTokenTest extends TestCaseWithSecrets
{   
    private Openssl $cipher;
    
    private $Jwt;

    public function setUp(): void
    {
        // Initialize the payload and cipher objects
        $this->Jwt = (new PayloadBuilder())
            ->setExpiration('+15min')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local')
            ->addField('random', bin2hex(random_bytes(16)));

        // Set up the cipher without keys for now (keys will be set during each test)
        $this->cipher = new Openssl();
    }

    /**
     * Test JWE encoding and decoding with the correct keys.
     */
    public function testJweEncodingToken()
    {
        // Set the keys directly on the cipher for this test
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        // Create the JsonWebToken instance with the configured cipher
        $JsonWebToken = new JsonWebToken($this->cipher);

        $algorithm = 'RSA-OAEP+A128GCM';
        $token = $JsonWebToken->create($this->Jwt, $this->publicKey2048, 'JWE', $algorithm);
        $this->assertIsString($token, 'Failed to generate a valid JWE token');

        // Set the private key again on the cipher for validation
        $this->cipher->setPrivateKey($this->privateKey2048);
        $valid = $JsonWebToken->validateToken($token, $this->privateKey2048);
        $this->assertTrue($valid, 'Token validation failed');
    }

    /**
     * Test JWE creation and validation with multiple algorithms.
     */
    public function testJweWithMultipleAlgorithms()
    {
        // Set the keys directly on the cipher for this test
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        // Create the JsonWebToken instance with the configured cipher
        $JsonWebToken = new JsonWebToken($this->cipher);

        $algorithms = ['RSA-OAEP+A192GCM', 'RSA-OAEP+A256GCM'];

        foreach ($algorithms as $algorithm) {
            $token = $JsonWebToken->create($this->Jwt, $this->publicKey2048, 'JWE', $algorithm);
            $this->assertIsString($token, "Failed to generate token with algorithm $algorithm");

            // Set the private key again on the cipher for validation
            $this->cipher->setPrivateKey($this->privateKey2048);
            $valid = $JsonWebToken->validateToken($token, $this->privateKey2048);
            $this->assertTrue($valid, "Token validation failed for algorithm $algorithm");
        }
    }

    /**
     * Test behavior when using incorrect private key for decryption.
     */
    public function testJweValidationWithIncorrectKey()
    {
        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $algorithm = 'RSA-OAEP+A128GCM';
        $token = $JsonWebToken->create($this->Jwt, $this->publicKey2048, 'JWE', $algorithm);
        $this->assertIsString($token);

        $this->expectException(InvalidArgumentException::class);
        
        // Set the wrong public key on the cipher for validation
        $this->cipher->setPublicKey($this->wrongPrivateKey);
        
        $this->expectException(InvalidArgumentException::class);
        // Set the wrong private key on the cipher for validation
        $this->cipher->setPrivateKey($this->wrongPrivateKey);
    }

    /**
     * Test malformed or tampered JWE tokens.
     */
    public function testMalformedJweToken()
    {
        $malformedToken = 'invalid.token.structure';

        // Set the correct private key for this test
        $this->cipher->setPrivateKey($this->privateKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $this->expectException(InvalidTokenException::class);
        $JsonWebToken->validateToken($malformedToken, $this->privateKey2048);
    }

    /**
     * Test JWE creation with unsupported algorithms.
     */
    public function testJweWithUnsupportedAlgorithm()
    {
        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $this->expectException(InvalidArgumentException::class);

        // Use an unsupported algorithm
        $JsonWebToken->create($this->Jwt, $this->publicKey2048, 'JWE', 'UNSUPPORTED_ALGO');
    }

    /**
     * Test token creation with empty payload.
     */
    public function testJweWithEmptyPayload()
    {
        $emptyJwt = new PayloadBuilder(); // Empty payload

        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $this->expectException(InvalidArgumentException::class);
        $JsonWebToken->create($emptyJwt, $this->publicKey2048, 'JWE', 'RSA-OAEP+A128GCM');
    }

    /**
     * Test expired JWE tokens.
     */
    public function testExpiredJweToken()
    {
        $expiredJwt = (new PayloadBuilder())
            ->setExpiration('-1 hour')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local');

        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $token = $JsonWebToken->create($expiredJwt, $this->publicKey2048, 'JWE', 'RSA-OAEP+A128GCM');
        $this->assertIsString($token);

        // Set the private key for validation
        $this->cipher->setPrivateKey($this->privateKey2048);

        // Expect validation to fail due to expiration
        $this->expectException(InvalidTokenException::class);
        $JsonWebToken->validateToken($token, $this->privateKey2048);
    }

    /**
     * Test JWE token issued in the future.
     */
    public function testJweTokenIssuedInFuture()
    {
        $futureJwt = (new PayloadBuilder())
            ->setIssuedAt('+1 hour') // Issued in the future
            ->setExpiration('+2 hours')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local');

        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $token = $JsonWebToken->create($futureJwt, $this->publicKey2048, 'JWE', 'RSA-OAEP+A128GCM');
        $this->assertIsString($token);

        // Set the private key for validation
        $this->cipher->setPrivateKey($this->privateKey2048);

        // Expect validation to fail as the token is not valid yet
        $this->expectException(InvalidTokenException::class);
        $JsonWebToken->validateToken($token, $this->privateKey2048);
    }

    /**
     * Test JWE token tampered after creation.
     */
    public function testTamperedJweToken()
    {
        // Set the keys on the cipher for token creation
        $this->cipher->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        $JsonWebToken = new JsonWebToken($this->cipher);

        $algorithm = 'RSA-OAEP+A128GCM';
        $token = $JsonWebToken->create($this->Jwt, $this->publicKey2048, 'JWE', $algorithm);

        $this->assertIsString($token);

        // Tamper with the token by altering its payload
        $tamperedToken = str_replace('.', 'tampered.', $token);

        // Set the private key for validation
        $this->cipher->setPrivateKey($this->privateKey2048);

        // Expect validation to fail due to tampering
        $this->expectException(InvalidTokenException::class);
        $JsonWebToken->validateToken($tamperedToken, $this->privateKey2048);
    }
}
