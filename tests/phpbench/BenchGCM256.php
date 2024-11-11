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
        $token = 'eyJhbGciOiJBMjU2R0NNIiwidHlwIjoiSldFIn0.70z55b66lcCeXmXdMVZlz7DlJDV0lITo9LNx9RP7xLOje1XYUHQ7B7388vEOwYQoMWG0jGStAgjKcuAXG47Hs1YXjt9tLrL2VW_tdB4OA07gK-Gz-10lzxrnTxRFQhM0.RklHajBGdzRxeDlmU2tsRWFZMmJsUEFtTUpmbHN0N09uT2F5SWdDbkZWMA.zWQ6ofcpcNzjwbmFfjRk0d8j30_qFGEL0xzIZxOBZ2r7dLCqfl6weC8_qsIhRHQIw0cFDUxyZg.FG9umZIUpZ0mx2k7Z0dp7A';
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
