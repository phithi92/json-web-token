<?php

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;

/**
 * Description of TestCaseWithSecrets
 *
 * @author phillip
 */
class TestCaseWithSecrets extends TestCase
{
    public array $publicKeys = [];
    public array $privateKeys = [];
        
    public function getPublicKey(int $bits){
        if( ! in_array($bits,$this->publicKeys)){
            $this->publicKeys[$bits] = file_get_contents(__DIR__ . "/../../tests/keys/$bits/public.pem");
        }
        
        return $this->publicKeys[$bits];
    }
    
    public function getPrivateKey(int $bits){
        if( ! in_array($bits,$this->privateKeys)){
            $this->privateKeys[$bits] = file_get_contents(__DIR__ . "/../../tests/keys/$bits/private.pem");
        }
        
        return $this->privateKeys[$bits];
    }
    
    protected string $secret16 = 'fbdc3ef88abf92b9';
    protected string $secret32 = 'fbdc3ef88abf92b9424715674a5de1ae';
    protected string $secret64 = 'fbdc3ef88abf92b9424715674a5de1aee3a37f05e437dd235ce67db2479da88a';
    protected string $secret128 = '8d9e501e67fb2d6d53c821016630f12457829fdfb7c6b63b47e662254c33be3fd0ced44765a7ae1961a7ac6e22c420d1222565ea93de62f11e11618edff18dc5';    
    
    
    public function createToken(
            string $algorithm, 
            ?string $passhrase = null, 
            ?string $publicPem = null, 
            ?string $privatePem = null
    ): string {
        $jwtAlgorithm = new JwtAlgorithmManager($algorithm, $passhrase, $publicPem, $privatePem);
        $factory = new JwtTokenFactory($jwtAlgorithm);
        $encryptedToken = $factory->create($this->getPayload());
        
        $this->assertIsString($encryptedToken, 'Token sollte ein String sein');
        return $encryptedToken;
    }
    
    public function decryptToken(
            string $algorithm, 
            string $token,
            ?string $passhrase = null, 
            ?string $publicPem = null, 
            ?string $privatePem = null
    ){
        $jwtAlgorithm = new JwtAlgorithmManager($algorithm, $passhrase, $publicPem, $privatePem);
        $factory = new JwtTokenFactory($jwtAlgorithm);
        $this->assertIsString($token);
        $decryptedToken = $factory->decrypt($token);
        $this->assertInstanceOf(JwtTokenContainer::class, $decryptedToken);
    }
    
    private function getPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setExpiration('+1 minutes')
            ->setAudience('localhost');
    }

}
