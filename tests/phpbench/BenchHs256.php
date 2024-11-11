<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchHs256 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('HS256', self::$SECRET32);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('HS256', self::$SECRET32);
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.YrFe1ubMA1RKQsl-Sj6jDhMnPNyAWLgFp5WDUVyWerY';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('HS256', self::$SECRET32);
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjA5ODUsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjA5ODUifQ.Fvizz1eTVt892wo7dmzU3pugHjjTaVX96o0MospQCkw';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('HS256', self::$SECRET32);
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.xZxa1pYI-7NURaC96M-7yQBaSXoOvN_Btp9QX15lLkM';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
