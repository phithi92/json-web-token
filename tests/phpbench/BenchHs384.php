<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchHs384 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('HS384', self::$SECRET64);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('HS384', self::$SECRET64);
        $token = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.HR7IDZLOZd267gbn9A8vYYAR_4bozwmhyeF_yfxZnJloy1WropA6Unv88o-7yLq7';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('HS384', self::$SECRET64);
        $token = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjExNzAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjExNzAifQ.0Nifl_BaJjji5FRDvf8evvsRkvrT24Ty190JdVygGnaq5p-65_Nz-VDlTMcvPXgT';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('HS384', self::$SECRET64);
        $token = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.au1w5GGgD_zSaSfJoyFwnh9F_f3L2fBPc9dCEjxePF3OoUpsILUrP3aheBNplINi';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
