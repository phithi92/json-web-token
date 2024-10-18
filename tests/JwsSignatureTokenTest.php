<?php

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JsonWebToken;
use Phithi92\JsonWebToken\PayloadBuilder;
use Phithi92\JsonWebToken\Security\Openssl;

require_once __DIR__ . '/TestCaseWithSecrets.php';

class JwsSignatureTokenTest extends TestCaseWithSecrets
{
    public function testJwsSignatureTokens()
    {
        // Create the payload
        $Jwt = (new PayloadBuilder())
            ->setExpiration('+15min')
            ->setIssuer('localhost.local')
            ->setAudience('api.localhost.local')
            ->addField('random', bin2hex(random_bytes(16)));

        // Initialize the Openssl cipher
        $cipher = (new Openssl())
            ->setPrivateKey($this->privateKey2048)
            ->setPublicKey($this->publicKey2048);

        // Initialize JsonWebToken with cipher
        $JsonWebToken = new JsonWebToken($cipher);

        // List of algorithms and keys
        $algorithms = [
            // Symmetric algorithms (HS256, HS384, HS512)
            ['encrypt' => $this->secret64, 'decrypt' => $this->secret64, 'algo' => 'HS256', 'type' => 'JWS'],
            ['encrypt' => $this->secret64, 'decrypt' => $this->secret64, 'algo' => 'HS384', 'type' => 'JWS'],
            ['encrypt' => $this->secret128, 'decrypt' => $this->secret128, 'algo' => 'HS512', 'type' => 'JWS'],

            // Asymmetric algorithms (RS256, RS384, RS512)
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'RS256', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'RS384', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'RS512', 'type' => 'JWS'],

            // Elliptic Curve algorithms (ES256, ES384, ES512)
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'ES256', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey3072, 'decrypt' => $this->publicKey3072, 'algo' => 'ES384', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey4096, 'decrypt' => $this->publicKey4096, 'algo' => 'ES512', 'type' => 'JWS'],

            // Probabilistic Signature Scheme (PS256, PS384, PS512)
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'PS256', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'PS384', 'type' => 'JWS'],
            ['encrypt' => $this->privateKey2048, 'decrypt' => $this->publicKey2048, 'algo' => 'PS512', 'type' => 'JWS'],
        ];

        // Iterate through each algorithm and perform the test
        foreach ($algorithms as $algorithm) {
            $this->createAndValidateToken($JsonWebToken, $Jwt, $algorithm['encrypt'], $algorithm['decrypt'], $algorithm['algo'], $algorithm['type']);
        }
    }

    /**
     * Creates and validates a token.
     *
     * @param JsonWebToken $JsonWebToken
     * @param PayloadBuilder $Jwt
     * @param string $encryptKey
     * @param string $decryptKey
     * @param string $algo
     * @param string $type
     */
    private function createAndValidateToken(JsonWebToken $JsonWebToken, PayloadBuilder $Jwt, string $encryptKey, string $decryptKey, string $algo, string $type)
    {
        // Create the token
        $token = $JsonWebToken->create($Jwt, $encryptKey, $type, $algo);
        $this->assertIsString($token, "Token creation failed for algorithm: $algo");

        // Validate the token
        $isValid = $JsonWebToken->validateToken($token, $decryptKey);
        $this->assertTrue($isValid, "Token validation failed for algorithm: $algo");
    }
}