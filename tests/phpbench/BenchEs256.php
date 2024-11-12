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
        $token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.GBB1Q67muoQo4dDQHi63ywVBJYZo_Kw75NyUpvcij8AXCkbDmO_zzVqmOef6Fcn0mFBgam4DkluygcdB7KFKphPajJg2fcnVLl_PIQhmabmBkNw6a4Ub_kQH1PNfADrnBP59i0esaUsuycNrstgczdK-FMnQe3HTgOxr3i4fRiFDXkUDjZO9lsojb-YO5VF7tlfpgQpM0aaGVBRFx0EOPw2iOE5gct_3KBXlg6nT2OOC4WLKePyWfirnOlZRkzyWd0lDhEClYwBKLTrMbeRi5AS-ZoNPxBbOB2NWAFd7YrMcIJHRJ9m65BXpUTJAYiMByq4IDJam3FwOYBtZMyEXYw';
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
