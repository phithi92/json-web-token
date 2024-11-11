<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchHs512 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('HS512', self::$SECRET128);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('HS512', self::$SECRET128);
        $token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.qwktIh9seSH3zOPurLRFrNrnEqYpkNyp2kKtJlW7udMZpE23wJPhfHuM32n1yFnNIjjQBPY4ulcgMjYBcgdW5g';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('HS512', self::$SECRET128);
        $token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjExNzAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjExNzAifQ.tK4CuKbLPjCUyBrBSvC9wbVXldjNzbVhXuvfMmxGI5sXEZw3K2_5UZwjaM4il5ufINjOs0CJW4ObGYuAPV_PYA';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('HS512', self::$SECRET128);
        $token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.gKeA4Clk0koFDga6PXzESLDPIPPVfPrnNeW01rN2PX6nYafSwpENmymUA_fwmtkGeelszQptQQXpNGPnT-fgWw';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
