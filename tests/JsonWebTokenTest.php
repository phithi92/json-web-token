<?php

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\JwtTokenContainer;

require_once __DIR__ . '/TestCaseWithSecrets.php';

class JsonWebTokenTest extends TestCaseWithSecrets
{
    
    private $payload;
    
    public function setUp(): void
    {
        parent::setUp();
        $this->payload = (new JwtPayload())
            ->setExpiration('+15 minutes')
            ->setAudience('localhost');
    }
    
    
    public function testValidHs()
    {
        $this->testAlgorithmEncoding('HS256', $this->payload, $this->secret32, '', '');
        $this->testAlgorithmEncoding('HS384', $this->payload, $this->secret64, '', '');
        $this->testAlgorithmEncoding('HS512', $this->payload, $this->secret128, '', '');
    }
    
    public function testValidRs()
    {
        $this->testAlgorithmEncoding('RS256', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('RS384', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('RS512', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
    }
    
    public function testValidEs()
    {
        $this->testAlgorithmEncoding('ES256', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('ES384', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('ES512', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
    }
    
    public function testValidPs()
    {
        $this->testAlgorithmEncoding('PS256', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('PS384', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('PS512', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
    }
        
    public function testValidRsaOaep()
    {
        $this->testAlgorithmEncoding('RSA1_5', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('RSA-OAEP', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
        $this->testAlgorithmEncoding('RSA-OAEP-256', $this->payload, null, $this->publicKey2048, $this->privateKey2048);
    }
    
    public function testValidGcm()
    {        
        $this->testAlgorithmEncoding('A128GCM', $this->payload, $this->secret16, '', '');
        $this->testAlgorithmEncoding('A192GCM', $this->payload, $this->secret64, '', '');
        $this->testAlgorithmEncoding('A256GCM', $this->payload, $this->secret128, '', '');
    }
    
//    public function testValidAesKW()
//    {
//        $this->testAlgorithmEncoding('A128KW', $this->payload, $this->secret16, '', '');
//        $this->testAlgorithmEncoding('A192KW', $this->payload, $this->secret32, '', '');
//        $this->testAlgorithmEncoding('A256KW', $this->payload, $this->secret64, '', '');
//    }
    
//    public function ecdh()
//    {
//
//        // Test algorithms that require only a passphrase
//        $this->testAlgorithmEncoding('ECDH-ES+A128KW', $jwtPayload, null, $pem2048['publicKey'], $pem2048['privateKey']);
//        $this->testAlgorithmEncoding('ECDH-ES+A192KW', $jwtPayload, $this->secret64, '', '');
//        $this->testAlgorithmEncoding('ECDH-ES+A256KW', $jwtPayload, $this->secret64, '', '');
//        $this->testAlgorithmEncoding('A128CBC-HS256', $jwtPayload, $this->secret64, '', '');
//        $this->testAlgorithmEncoding('A192CBC-HS384', $jwtPayload, $this->secret64, '', '');
//        $this->testAlgorithmEncoding('A256CBC-HS512', $jwtPayload, $this->secret64, '', '');
//        $this->testAlgorithmEncoding('chacha20-poly1305', $jwtPayload, $this->secret64, '', '');        
//    }
    
    private function testAlgorithmEncoding(string $algorithm, JwtPayload $jwtPayload, ?string $passhrase,string $publicPem, string $privatePem)
    {
        $jwtAlgorithm = new JwtAlgorithmManager($algorithm, $passhrase, $publicPem, $privatePem);
        $factory = new JwtTokenFactory($jwtAlgorithm);
        $token = $factory->create($jwtPayload);
        $this->assertIsString($token);
        $decryptedToken = $factory->decrypt($token);
        $this->assertInstanceOf(JwtTokenContainer::class, $decryptedToken);
    }
}
