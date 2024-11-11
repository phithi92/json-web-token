<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchGCM128 extends \BenchmarkBase
{        
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('A128GCM', self::$SECRET16);
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('A128GCM', self::$SECRET16);
        $token = 'eyJhbGciOiJBMTI4R0NNIiwidHlwIjoiSldFIn0.U8LnKZ_w4LPBtpF1PO6IyOzorGtkjS9sXgpFfG6wN7o4Juhp5vN3z9CCgRQZ__COrG0Zd-v9ScyHpIvRhfbJ5Fntm9j_fdVuJpLr5rJ5NycPFMHKCaZRLOERciSG9e-8.a2ZCMkQxR3o4N3FmaDNwZ3FBSUFuQQ.MooNHuxjM3_WiB4rA__lWDoyx5UKvtzGC6aPFY9HgxiMX0Kumwr1uj5nYdGYiH-AzfpbMrw_4w.tb798VhnJLCJjlVEvWrFDg';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('A128GCM', self::$SECRET16);
        $token = 'eyJhbGciOiJBMTI4R0NNIiwidHlwIjoiSldFIn0.kkvNIhdbMoD2egVwIb0UJKLPnZOeCx6lomFEAnLYKCBgpHvUenwm0HNGRlwuh0YHseMAhRjsN9-RhZHnYDS0DZTNPV9qxW6HREsXMuM6BN3Bw6vE85N9aSO189yTkhYd.NW0zdnk1U3ZFUTNWS0tSRXlRaWlWdw.8AZYXfmIXdPLW0a__kLQyCJb-5fFI2qXsG76d4hueWqeJejDzHG0Sqr9I4NhUHM7xR8rzXCVIg.ZDp1m-p0qTc_9hW80q3ItA';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(\Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('A128GCM', self::$SECRET16);
        $token = 'eyJhbGciOiJBMTI4R0NNIiwidHlwIjoiSldFIn0.kgKZwPhivwZddxpoyeI1fGShOFI8gotasS5RFInKGGaE7xr6YOjhVtkrDPZs7TWUcA43fRkGjRbNSrVuaK3bwsTUXezhWza9O5VtsuTCjR7Az-B9LVxmidzsoXgHjnuE.SktVNlVGZ01FUWJsTjdWNnpVSW82UQ.6vv1I7e4f3SaI249qUvr_nB4IusgUGyBSfRu9cZCs2i5yW-_OLoK1PL8medAzDtfV0dj1EN0Cg.Hr4MkHT9KniQm2fCVhGxMA';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(\Phithi92\JsonWebToken\Exceptions\Cryptographys\DecryptionException){
            
        }
    }    
}
