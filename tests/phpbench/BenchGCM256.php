<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchGCM256 extends \BenchmarkBase
{        
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('A256GCM', self::$SECRET64);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('A256GCM',  self::$SECRET64);
        $token = 'eyJhbGciOiJBMjU2R0NNIiwidHlwIjoiSldFIn0.yuGyXrurOmdn-lqZLSiK7VISfer36vCYv5w8YyywbNWRC6HnfNgWj0JdQkNdwz622R-lkMecmT3JUGmvuDTdjH0UZt14g6OEhc_qlMqwGgVZwxp5FGw3UNx_vEbDyvHK.UmxWdlItNENraFBzYTNXV2lzSUlaMU9aSS1XYjRQNGR6WmZCN1BQUEh3bw.GCfLdqPQjauaXXyy-9ltoytGDp90GAg1c6gPY6iEgeSM1Rq9GN16iurJrl6tt0s0ONAQOG4.GNZnFKpfTS1dQjHuQAgP8Q';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('A256GCM',  self::$SECRET64);
        $token = 'eyJhbGciOiJBMjU2R0NNIiwidHlwIjoiSldFIn0.xUxxRNqrAWwofLwOHvRZtKb7KU8p_CAhs_omIurIAhjzkfDZ6uJi_1LZc51LBfQ62K4oFDPMUMvJpjve9k8PTYckzXMhSAM2UTeSL1m29wPMBGeVCbSalrLecqPwPHyw.cDlsYkFocUZTSjBJaC16eWVPbmNNd2R5RG1CM2t0cTBWYU5ZVTk2eUlRQQ.FXZnsH53rskWIGt06IQbvF0kQeKUdKKPu_DW-af1HJKug2VmWVweRZx6JG16tCMsRJYGFc8VcA.oo6QEMeVa9o_TntdV8XpJQ';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('A256GCM',  self::$SECRET64);
        $token = 'eyJhbGciOiJBMjU2R0NNIiwidHlwIjoiSldFIn0.kcm554FaCUrB6Vi6t4T_NCqDSz7lXNk7zmFUdalxroRdEWFSH0Mtir9l3Oxbkw88bNv1UHz-V771tBcb4XK8qyP7MO12N-OIbA79k4jjb1IQU_QzZ3vPWJkRUlA-lOCT.aFhYUWt0V1NrajlVdndUR2VlQTNwZl82Z3ZfQnJQUzg3cjFMb01OckhEOA.6EA7hI2GdXUkFu1nZFDLgUwcZxKexm6sbjYsjZmKD_RPtlytDjG8iWFoIcHwKH9sY2pKrbxgww.3K0WrDD8PtkOVWJE_ttClA';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(\Phithi92\JsonWebToken\Exceptions\Cryptographys\DecryptionException){
            
        }
    }
}
