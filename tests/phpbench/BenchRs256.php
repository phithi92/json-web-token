<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchRs256 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('RS256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('RS256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.n3Ibc6IM75w565mq3DVMZX9MlT5vhOUH-b2BM-1_dtzStVzSVCrTamN0Mp8efwMmBU96ols6KDYsxzbrGPqB4STN9-Fb1hTrk31M5Gaj0IhwZr2WsXTnjNAqaZD_HKojGyebf7HbPy_masDafaWc2B3qp_fR4LArKzc0njrzwXS4DN7aljtH9QW8eUChnkOLVIKcD-IjeGfVR5nEiwfXjyc2bsOkVVS_rgC0Cn32in3PxuPWk-rfVq8X2y-3G6h-3D8Th_w22-HxS_3tsMd-CaKhtOgZBS1xxxB1Gcx1uTDzH1-YXbSpJStg8tt2Q-PNhDCbiLmsE-EoH1MxPi-KDw';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('RS256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.iCdmWvxb35p0fw-wlurc7y7eIFa2OvKNOtA6TjQhndOssJukXJp-0JkH-RqwHC34tnPNjTnFnGFilVhdGhi0Ho5IErz7kFqQshzIOmQYGW5sZ4kawPs0tvsXWdvWymINGEZcYzlU-og6tv5ySiY_4uZLcpB_OHgD9x1P1ZqR_qiooRqKZEQUnb8bzoPVDdIrkp56qQauD6wlZxaahkko1bS6B4hCgPYW9JdPkDnEFCNhVuVDlbvF-bxQ6SX_1hv8UYwRvx82a2F1TCUBGw2lHY8sC6rtAMEHZtQyJR5NKP6NEIgNeEVH6YBoN7X1aFxRnWkkNqO0CSXcX9Km3Y1XEg';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('RS256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.Q1EiO8Cdf7DX0m186PlYOIjP0xBYIWFXwXn2csDrEsCYWl0NHzdMm2vyfwZQeSXDQHRmwlRZqjB6PN-jBsryCnnFzvVSM0BjnCFS7CCWBo_zkKe7kXL_N8jpM8Ag04fqdm6JXfOdZPfqwWIikXLvBkLPMrU4nH48Qc1oh6Y0BAJgsWxDB0Syu4-iHb32xdxVWPT2pXKH1Sivh_MyFDYNxZhSn87GgntNYxwp9YGG6vnKQtvZXakTfXEM2wel88d3e3jxkpagDDvDrOVsLjfC-3SGTv9Iz8b9gwKJDwHpbmDxmGBcGHsdzF3GcBcAFO0G3xKv5nPh5HAIqzNWU4mqtg';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
