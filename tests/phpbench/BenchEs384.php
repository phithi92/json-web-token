<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchEs384 extends \BenchmarkBase
{
    // Benchmarks für die RSA-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('ES384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }

    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('ES384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.HgGMsCMQAhGJ6YTBDSUW4l5rtKHmcNHkR5U__XmJ5NIwVzPEWR-GrUCi2V6gflU_2AfdjWQEnBbv4493ybFvWtRqCB2mYbIjNI_FENPN53vWQ-iQf7KKyOCHAVfqwWdRoysIlT4zFetsyYiJ3lI2Kxw9rPtHEYrPe4kYIpi0SLbXigCgOlsjnBtLIrLA2nVhu-JUma5Bj6LgO_qHEXuUxRUU8_jywZLrXakJ3NAQmisysFpMmlnC2nCfUKO5F44qjWVkMZ-15DLPfbeG7gkDCzlA2sknW3gh4O-_fcK4WEmVf-lsXhs4-mSCBjdVWdd_8ubuwWXwdyQ1GblGxUsyvfXreFd0JeSNQMlt-QCT1wAsffhbNg68Krvp8L0A_Mnj43bAj5X_6ld1i6eIReN-iRfraB4aK8pA3IxaQxGK1JBt8BlIHiTdvxFe9WGswFZU7DlwyZAjFiLgZv76z5HfiCvkdxPLfzx9svRDamDmkxJ-jRNfLlMi519gAvBaTDxK';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('ES384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        
        $token = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.IcMSNQPZwgwYkInrU-DAa8b2bWDEZimBWR5IsKj81cpG3q2tl9Lr-_isZKcl_cu2Y0Co6Dp_Q3BfhoWqUOeRD9jLASJlt1mFVANqYeLvqX0aM8s-cEsy-7CS9NOWJkMzfTrNIGM0LkPNGDWcxzneq6anCsW6cSGm0tjAmUTT2rMjmtLFOwXSFifCBzseozAJRQ1GcJgezm_kYaw6SB6Si2rvrdnZ0WeAXT0KjUv8_THa2weqZCYZFUrhSwqN3DNsojad6-zBwqGQMgQlsgGJl0WE6I1q1aSpTfRWfRrnWxpDUw_MHv4lhnp-0gjJ5fxG_kJWAPbPzPP3O6nhlSx535scZSfhfVKru3Au6royCY5RjftLHmlV1OHEbr4bp_ncOa5WeSTSOjuyHnlVt91t9kLHAaz_r1Enjtccc_FUFdtNFtRAkkoi-cJFQK16OAxsNWe3epSJUG0ioI161qdsY5K9xzGgGbco5B_rTP8qCPKaLxi6j64i0Pu2Q4AxsS5t';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('ES384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.gje98iIm9VkNP2wXYzust3g-Pzp7t2fiQ7p-hvqKopHsHkwwP_u0S0mCIByG6R8JEzqZ04Ys-6hpgRp-h07HrskwaRTOniBE6YeKKtxFYjYtFuwKTuJt_Rl_uou6p6oCV-ckAq6dy15deQjiRF9Ilby2smVCGgxyvr2ajx8Nyt51KjZJSrrSbKpSd9k1vzUQHfNQZi0meSSLWUP_N86my5oo8S7O93stsSyataRmXOe6V0bOfrqWB-dMBvWjXAtJ9-HvLjuHRl4R7tzxgS4A80BrDNVncplMrdEGG9u8c5IfTRKSaooUePeeWtsfptSyj-tBAmNrCJ4uTggzUmEXS585JNAkRXxX2vz_A4ig-toO3sKBqdhsFC14dob-8BuSjz1MnMeV_ydjnvgEjHK_Mzz5HqTf4-JR6zoGEMsZrvESYgRYXZor_2Irt6UipO6PuM8lXdE78HY6SfPU33NGlISfGfIqKlfuGfo7-O6UJPVTBtOkQAfnMLrGNWy_fnj9';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
