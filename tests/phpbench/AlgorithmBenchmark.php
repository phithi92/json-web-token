<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class AlgorithmBenchmark
{
    public static string $SECRET32 = 'b8bf03cf9cfd11ef8000b63dfc9e964b';
    public static string $SECRET64 = 'b8bf03cf9cfd11ef8000b63dfc9e964bb8bf03cf9cfd11ef8000b63dfc9e964b';
    public static string $SECRET128 = 'b8bf03cf9cfd11ef8000b63dfc9e964bb8bf03cf9cfd11ef8000b63dfc9e964bb8bf03cf9cfd11ef8000b63dfc9e964bb8bf03cf9cfd11ef8000b63dfc9e964b';
    
    private static array $MANAGER = [];
    
    private static function setupAlgorithmManager(
            string $algorithm,
            ?string $passphrase = null
    ): JwtAlgorithmManager {
        if(isset(self::$MANAGER[$algorithm])){
            return self::$MANAGER[$algorithm];
        }
        return new JwtAlgorithmManager(
            $algorithm,
            $passphrase,
            file_get_contents(__DIR__ . '/../../tests/keys/2048/public.pem'),
            file_get_contents(__DIR__ . '/../../tests/keys/2048/private.pem')
        );
    }

    private static function createPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuer('https://myapp.com')
            ->setAudience('https://myapi.com')
            ->setExpiration('+15 minutes')
            ->addField('user_id', 123);
    }
    
    private static function createAndDecryptWithStaticFunctions(
        JwtAlgorithmManager $manager, 
        JwtPayload $payload
    ){
        $encodedToken = JwtTokenFactory::createToken($manager, $payload);
        JwtTokenFactory::decryptToken($manager, $encodedToken);
    }
        
    // Benchmarks für die HMAC-Algorithmen
    public static function benchStaticEncryptionDecryptionHS256()
    {
        $manager = self::setupAlgorithmManager('HS256', self::$SECRET32);
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionHS384()
    {
        $manager = self::setupAlgorithmManager('HS384', self::$SECRET64);
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionHS512()
    {
        $manager = self::setupAlgorithmManager('HS512', self::$SECRET128);
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    // Benchmarks für die RSA-Algorithmen
    public function benchStaticEncryptionDecryptionRS256()
    {
        $manager = self::setupAlgorithmManager('RS256');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionRS384()
    {
        $manager = self::setupAlgorithmManager('RS384');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionRS512()
    {
        $manager = self::setupAlgorithmManager('RS512');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    // Benchmarks für die ECDSA-Algorithmen
    public function benchStaticEncryptionDecryptionES256()
    {
        $manager = self::setupAlgorithmManager('ES256');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionES384()
    {
        $manager = self::setupAlgorithmManager('ES384');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionES512()
    {
        $manager = self::setupAlgorithmManager('ES512');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    // Benchmarks für die RSASSA-PSS Algorithmen
    public function benchStaticEncryptionDecryptionPS256()
    {
        $manager = self::setupAlgorithmManager('PS256');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionPS384()
    {
        $manager = self::setupAlgorithmManager('PS384');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }

    public function benchStaticEncryptionDecryptionPS512()
    {
        $manager = self::setupAlgorithmManager('PS512');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }
    
    public function benchStaticEncryptionDecryptionRsaOaep()
    {
        $manager = self::setupAlgorithmManager('RSA-OAEP');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }
    
    public function benchStaticEncryptionDecryptionA128GCM()
    {
        $manager = self::setupAlgorithmManager('A128GCM');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }
    
    public function benchStaticEncryptionDecryptionA192GCM()
    {
        $manager = self::setupAlgorithmManager('A192GCM');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }
    
    public function benchStaticEncryptionDecryptionA256GCM()
    {
        $manager = self::setupAlgorithmManager('A256GCM');
        self::createAndDecryptWithStaticFunctions($manager, self::createPayload());
    }
}
