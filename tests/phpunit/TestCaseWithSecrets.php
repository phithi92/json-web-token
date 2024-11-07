<?php

use PHPUnit\Framework\TestCase;

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
}
