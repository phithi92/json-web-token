<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchEs256 extends \BenchmarkBase
{
        // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('ES256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('ES256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.Gr14nv73OyiEZtkD8AyLra2Edoxh0_kYbPylHRmN2mrwJqZQ_fkUGRiLvR0zuiPbkvH39yqE3owjbcC1iZyP5ch1McjlgDgHLkoonywOUVVzwFtAnAx9aJ3Ore1gquLqCBtMK_RDfxIZLnKYfeJgAQ15deBI_lr5tpN5jbHhozGvnTfeDyWgeNYcRBVHH1ClJueRIiGSkX73CTEjoqQI7P0lgs197-PRDob7QUKfpDQ9QAPq1qFG5g7ilDFfapi1bNpm9uCohG0yasgcIuMzEKyilkYH-bDrHUh-T6ZjqKOof_Y8q71UP8E6wGJ_WW2kmTXN9AUc2PHVcmSApKJwAg';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('ES256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.S8y2mepirfxw-GV-ltNjs3UiOu1Fv56leZ09dpBsk36Z50EPPVJOfVkCN6WSlCfCHaKN91y1J4QhiT_oLR21_QyHg5bGFOQDeFO1JJmdDZgp6WD4SjNLpt4MS0XJFq8k3fWNrdClFEQ1plN5wkBIXI8_7URXalFFh2bHBSEp6g4T5PrCv3Qf1cv1QINwGet5axxg3qhhcHccZp0cK_aIipYdUfINwLa-hVyzKIwQE0Moxzu7HNmF67WT3uDhe42lhYYd9T2DBpE856gOq1zpqu_puWoV56prVl-9s3NHJ2T2AcnKxKEOnyCvnx4WSxPefZXkz2nPGZ0SPS3Kle6SCg';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('ES256', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.S-cXFhQ6EkSiuUhtXFj-ywAeJS1KmAnr35A5n5En3QPj44BRcjAKia8wlE20AWaUgt3W_6s9h3UJwH1bOG82z54iX3AXbX355iTDMCSDjER-ba240811ujaIro_AKJxfn1rWbW0AfqMO7hQLhnuqQ7dsyDFWeoyxJ-nosbiKC-NYAGKc0AxdizOkRDArRxBW2fQN2fYlB0RSZj_d98QPZHJlpwguf0tP-zAKL4ikzim23TvVvtGgK_i7rA8Ivtg6suzIKqqImP4zB57YuU46xpUYd_qH6cBUrakGH87ebtp7HbQoa3qQnoOyn3bB9cKB6k1LlQ9ZDJBU1H2Wp3pLvw';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
