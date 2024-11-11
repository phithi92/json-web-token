<?php

use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;

require_once __DIR__ . '/TestCaseWithSecrets.php';

final class JwtTokenFactoryTest extends \TestCaseWithSecrets
{
    private JwtAlgorithmManager $cipherSymmetric;
    private JwtAlgorithmManager $cipherAsymmetric;
    private JwtPayload $payload;
    private JwtTokenFactory $jwtTokenFactorySymmetric;
    private JwtTokenFactory $jwtTokenFactoryAsymmetric;

    protected function setUp(): void
    {
        // Initialize Algorithm Manager and Payload for symmetric algorithm
        $this->cipherSymmetric = new JwtAlgorithmManager('HS256', $this->secret32);
        
        // Initialize Algorithm Manager for asymmetric algorithm
        $this->cipherAsymmetric = new JwtAlgorithmManager(
            'RS256', 
            null, 
            $this->getPublicKey(2048),
            $this->getPrivateKey(2048)
        );
        
        $this->payload = (new JwtPayload())
                ->addField('sub', 1234567890)
                ->addField('name', 'John Doe')
                ->setExpiration('+15 minutes');
        
        // Create JwtTokenFactory for both cipher options
        $this->jwtTokenFactorySymmetric = new JwtTokenFactory($this->cipherSymmetric);
        $this->jwtTokenFactoryAsymmetric = new JwtTokenFactory($this->cipherAsymmetric);
    }

    public function testCreateJwsTokenWithSymmetricCipher(): void
    {
        // Creates a JWS token with symmetric algorithm and checks if it has the expected format
        $token = $this->jwtTokenFactorySymmetric->create($this->payload);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token);
    }

    public function testCreateJwsTokenWithAsymmetricCipher(): void
    {
        // Creates a JWS token with asymmetric algorithm and checks if it has the expected format
        $token = $this->jwtTokenFactoryAsymmetric->create($this->payload);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token);
    }

    public function testDecryptJwsTokenWithSymmetricCipher(): void
    {
        $token = $this->jwtTokenFactorySymmetric->create($this->payload);

        // Decrypts the generated token and checks the payload data
        $decryptedToken = $this->jwtTokenFactorySymmetric->decrypt($token);
        
        $this->assertInstanceOf(JwtTokenContainer::class, $decryptedToken);
        $this->assertEquals('1234567890', $decryptedToken->getPayload()->getField('sub'));
        $this->assertEquals('John Doe', $decryptedToken->getPayload()->getField('name'));
    }

    public function testDecryptJwsTokenWithAsymmetricCipher(): void
    {
        $token = $this->jwtTokenFactoryAsymmetric->create($this->payload);

        // Decrypts the generated token and checks the payload data
        $decryptedToken = $this->jwtTokenFactoryAsymmetric->decrypt($token);
        
        $this->assertInstanceOf(JwtTokenContainer::class, $decryptedToken);
        $this->assertEquals('1234567890', $decryptedToken->getPayload()->getField('sub'));
        $this->assertEquals('John Doe', $decryptedToken->getPayload()->getField('name'));
    }

    public function testRefreshTokenWithSymmetricCipher(): void
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-5 minutes')
                ->setExpiration('+5 seconds');
        
        $token = $this->jwtTokenFactorySymmetric->create($payload);

        // Refreshes the token and checks if the expiration was updated
        $refreshedToken = $this->jwtTokenFactorySymmetric->refresh($token, '+2 hours');
        
        $decryptedToken = $this->jwtTokenFactorySymmetric->decrypt($refreshedToken);

        // Verifies that the refreshed token has a newer "iat" time
        $this->assertGreaterThan($payload->getIssuedAt(), $decryptedToken->getPayload()->getIssuedAt());
    }
}
