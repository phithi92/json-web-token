<?php

require_once __DIR__ . '/TestCaseWithSecrets.php';

use Phithi92\JsonWebToken\JwtPayload;

class AlgorithmsTest extends TestCaseWithSecrets
{
    
    public JwtPayload $payload;
    
    public function setUp(): void
    {
        parent::setUp();
    }
    
    public function testEncryptHs256(): string
    {        
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('HS256', $this->secret32, '', '');
    }
    
    /**
     * @depends testEncryptHs256
     */
    public function testDecryptHs256(string $token)
    {
        $this->decryptToken('HS256', $token, $this->secret32, '', '');
    }
    
    public function testEncryptHs384(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('HS384', $this->secret64, '', '');
    }
    
    /**
     * @depends testEncryptHs384
     */
    public function testDecryptHs384(string $token)
    {
        $this->decryptToken('HS384', $token, $this->secret64, '', '');
    }
    
    public function testEncryptHs512(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('HS512', $this->secret128, '', '');
    }
    
    /**
     * @depends testEncryptHs512
     */
    public function testDecryptHs512(string $token)
    {
        $this->decryptToken('HS512', $token, $this->secret128, '', '');
    }
    
    public function testEncryptRs256(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('RS256', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptRs256
     */
    public function testDecryptRs256(string $token)
    {
        $this->decryptToken('RS256', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptRs384(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('RS384', null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    /**
     * @depends testEncryptRs384
     */
    public function testDecryptRs384(string $token)
    {
        $this->decryptToken('RS384', $token, null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    public function testEncryptRs512(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('RS512', null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    /**
     * @depends testEncryptRs512
     */
    public function testDecryptRs512(string $token)
    {
        $this->decryptToken('RS512', $token, null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    public function testEncryptEs256()
    {
        return $this->createToken('ES256', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptEs256
     */
    public function testDecryptEs256(string $token)
    {
        $this->decryptToken('ES256', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptEs384(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('ES384', null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    /**
     * @depends testEncryptEs384
     */
    public function testDecryptEs384(string $token)
    {
        $this->decryptToken('ES384', $token, null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    public function testEncryptEs512(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('ES512', null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    /**
     * @depends testEncryptEs512
     */
    public function testDecryptEs512(string $token)
    {
        $this->decryptToken('ES512', $token, null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    public function testEncryptPs256()
    {
        return $this->createToken('PS256', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptRs256
     */
    public function testDecryptPs256(string $token)
    {
        $this->decryptToken('PS256', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptPs384(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('PS384', null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    /**
     * @depends testEncryptPs384
     */
    public function testDecryptPs384(string $token)
    {
        $this->decryptToken('PS384', $token, null, $this->getPublicKey(3072), $this->getPrivateKey(3072));
    }
    
    public function testEncryptPs512(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('PS512', null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    /**
     * @depends testEncryptPs512
     */
    public function testDecryptPs512(string $token)
    {
        $this->decryptToken('PS512', $token, null, $this->getPublicKey(4096), $this->getPrivateKey(4096));
    }
    
    /**
     * @depends testEncryptRSA1_5
     */
    public function testDecryptRSA1_5(string $token)
    {
        $this->decryptToken('RSA1_5', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptRSA1_5()
    {
        return $this->createToken('RSA1_5', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptRSA_OAEP
     */
    public function testDecryptRSA_OAEP(string $token)
    {
        $this->decryptToken('RSA-OAEP', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptRSA_OAEP(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('RSA-OAEP', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptRSA_OAEP_256
     */
    public function testDecryptRSA_OAEP_256(string $token)
    {
        $this->decryptToken('RSA-OAEP-256', $token, null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    public function testEncryptRSA_OAEP_256(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('RSA-OAEP-256', null, $this->getPublicKey(2048), $this->getPrivateKey(2048));
    }
    
    /**
     * @depends testEncryptA128GCM
     */
    public function testDecryptA128GCM(string $token)
    {
        $this->decryptToken('A128GCM', $token, $this->secret16, null, null);
    }
    
    public function testEncryptA128GCM(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('A128GCM', $this->secret16, null, null);
    }
    
    public function testEncryptA192GCM(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('A192GCM', $this->secret32, null, null);
    }
    
    /**
     * @depends testEncryptA192GCM
     */
    public function testDecryptA192GCM(string $token)
    {
        $this->decryptToken('A192GCM', $token, $this->secret32, null, null);
    }
    
    public function testEncryptA256GCM(): string
    {
        // Gebe den Token-String zurück, um ihn im nächsten Test zu verwenden
        return $this->createToken('A256GCM', $this->secret64, null, null);
    }
    
    /**
     * @depends testEncryptA256GCM
     */
    public function testDecryptA256GCM(string $token)
    {
        $this->decryptToken('A256GCM', $token, $this->secret64, null, null);
    }    
}
