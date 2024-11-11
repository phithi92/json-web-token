<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;

abstract class BenchmarkBase
{
    public static string $SECRET16 = 'fbdc3ef88abf92b9';
    public static string $SECRET32 = 'fbdc3ef88abf92b9424715674a5de1ae';
    public static string $SECRET64 = 'fbdc3ef88abf92b9424715674a5de1aee3a37f05e437dd235ce67db2479da88a';
    public static string $SECRET128 = '8d9e501e67fb2d6d53c821016630f12457829fdfb7c6b63b47e662254c33be3fd0ced44765a7ae1961a7ac6e22c420d1222565ea93de62f11e11618edff18dc5';    

    public static function setupAlgorithmManager(
            string $algorithm,
            ?string $passphrase = null,
            ?string $privatePem = null,
            ?string $publicPem = null
    ): JwtAlgorithmManager {

        return new JwtAlgorithmManager(
            $algorithm,
            $passphrase,
            $publicPem,
            $privatePem
        );
    }
        
    public static function createPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuer('https://myapp.com')
            ->setAudience('https://myapi.com')
            ->setExpiration('+15 minutes')
            ->addField('user_id', 123);
    }
    
    public static function getPem(string $type, int $bits)
    {
        return file_get_contents(__DIR__ . '/../../tests/keys/'.$bits.'/'. $type .'.pem');
    }
}