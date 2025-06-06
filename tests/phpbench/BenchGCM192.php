<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchGCM192 extends \BenchmarkBase
{        
   
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('A192GCM', self::$SECRET32);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }

    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('A192GCM', self::$SECRET32);
        $token = 'eyJhbGciOiJBMTkyR0NNIiwidHlwIjoiSldFIn0.k16TF-QIy-sbpSN5TLBtdO29RwCHFK2WSPn7wEe1mFdol4_OrmzEqFkkiY4CqNXKzuCcxsFE67ZPiyzhpBuU-wg1dDzT14OdwldUU2VBFIrNYn6LFTzPXC1LQIs4FswT.NG1oSm5pQXJjXzVMQWxuZEp4SnlHTVBDaUFFRm5jeW0.kDW7E2ttlpeQ3Ylgv5Xrsl0XTSKEYvbyFF9jl-X1tWWOcKo-m2RhL7klk30usb_gnrTREys.YQbi5AhG_FkAmhmapYasag';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('A192GCM', self::$SECRET32);
        $token = 'eyJhbGciOiJBMTkyR0NNIiwidHlwIjoiSldFIn0.H5ko7Ti8IkO3u9-Hi-8MGMKZeuSRplsbR8K4h9bwyxqo4qkY3xF9yPQ3y0w04th9zEigBCsoGuw8Mu4YznfvVGV67F9G7-a3U0uEt0SpV6X4e13goKpO1DVyAU2z-2UJ.aVBmLWg1bFc2WEJKSjhib1dOTEUyY3luS2NGVGVxblI.1kUQiILt5XH2SvwMjFpgKbV-eDhwosYB0pgblGzofXkGEI0nZhomhzFwqaoOoGucMyZHiXnafg.MAWFZJ1qIaxoUznhUSuJuQ';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(\Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('A192GCM', self::$SECRET32);
        $token = 'eyJhbGciOiJBMTkyR0NNIiwidHlwIjoiSldFIn0.kDBq8OVe1VWSINhIR3tet__meMu0iQK7iqnhaU9IZihtdKULSgEjLhW_iZMmhWQLVYf7ShDeYEFwr6I1D5gbxsOERt-pc5_op613w4V5DGVkYKRUtgOcL2IrOXugFqQy.RG1HN1kyUTFldlFIUExFS2dUN29lZWJhWDZDa1Q3Z0s.wVOhr_3UrXMg0OtDuDyYLGE4xQrA0OQ7ifXRpkhSqN_f5tCRUHJAQxD7iYAwYDbeBzmU-4K2Cg.6_uY75SJaNUqwL7A59S_FQ';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(\Phithi92\JsonWebToken\Exceptions\Cryptographys\DecryptionException){
            
        }
    }
}
