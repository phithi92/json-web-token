<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchPs384 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('PS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('PS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.Tzp0Ydtqfqdz8YUCR4OxDOsnlR647cn43Qbz_YC-k6zsHpx6cBG-OglyIOkGrVYmj63JXDtuAAlKDsQ4K9C4W09ajB0lzecOa1x2nidRHXEK-QY6Im6T_J3GD5B-n2k5itWTn-G5eLUu7mfEL9Svmrhc_JGfRgcJEtU4BQpep6YfQmQpV4XwVO_d1Wecde-JKPySbYL7LlB6YKukOyb5uRGchlBSMxSHT42w_1jrIr2a7LfpvxxwY-AIvmS1XtQRS4tQm-cYDGYBV8GVKeFngiceCImGMBEvZ23O29vRLCEZ_jb-LjTJLX-3vVi6X4B7KgoVRyEJhxhZj1M1D-9T1jqRPPV4qctsm6K1IA288n5MiqhTojaS_zHK605A-rA0oQY2qt1oV4bgFPnHVAnbC-DcAsb9jjZldrI9k7G5NSGyTTWQWjpA0fuPwUzzZwHxPvUlRrTP5hfqHzNsY2Ifzf7pW1BmkE3O0dzPF5JfOfQAsqwxqcNWVYd_nOnqpdTL';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('PS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.op7dyTs02aWCBaYDWEPr8sE2JArOMYYrRdnBKQc2ntbYWMI6PjL63nFg90ED-VmQDi0wz7aO47CW1jsTmKgoh_F7Ogh2yph74QC_96l7OqEgN8v_yY-eNqm1vuhWWiK0ina2keC2T2ZV1uq344PmmwjflodSEmMc5ZlnCz_OXnvp75k8BR0fdTF3MRGhxBAeTkQnjxfbL7PRY0e1VEGyJZXxfRLu804GnHYHX2mDhbLf5JPLagZtuB1o9psw4d5wuibph7V64dhqQLKe-ll1GMeNjSt_zX2MpQmA7j5IMM1Qxzpf662GLKBQd6HSkutPNsKmaHfYZ9oZE39nCUdjvYzQ853OOmi0kcSuGgwNnxne4_S5pisYsvZgeviLY_euu11zTpVAgijeAQmpoMw7qsYbRQByMFLepmLxTruldbTPoW6xT6HGrgL5um-R2tDDF755-ksKcGBd7mDz88qXDk-jpsw8rLtnZ04J3acWdO9D75hm-af4uWriwNq6KuCtYcgqH0QqdyJeZQpKv4tcdc39yo_8WxIrlhjl6dEU6d_L5aUT10hhYvB0zUUyrTFTvzG--qDb8SciUid5DD-iVgWw1uI_E2KrnLmHTpantQ4T_4zEWxyWr1wokDfhclGfRxFRuDHt8TAtq5iBtkb-Sj3hXp4clfHKSHUgGwosVd0';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('PS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.Wjp2E-E2jUU-DhATBQRWqpIP1D-GeJ91OI4Ck0nHhVjhfnfHqvoIrRb1M9xVD34WfCg-TBN55KKGPSqbtUEntC3aJy1jtdq7Lv2jGX-Q9gTjkw0F9sLCApHn6E0-r3yg7waAogLGc68VV43o8In7p-QNq-StlR-Ald0AmRR2iNzWG32WsD8cd-DR9JFu812GxwTKUT_R_b4OAXY5IIIcYAz0YIpGm9Ed7Ciq1rmgUSqwFbZ8czClODDeO2qDns6GBE-wm_ylV96R_NYbLjXekkzxwFJNrlWoPIRnNIhdVF18uvNmUvfbx5AQON12c4ofAtGKJjez9WeXlxWzfBd9xcncycj0EJv-6-8cNdu3CmXIqnTLEOe5NDh0JMQVPLNOzV33GQLqnBn9ciRDyAFWdoGfW5vtIGcEcG4x9oUiBjXPLAnZIQoDuXtYBEJConHdKLLNAUouUCNlxQiQWTNMNjLS1vtVJ08GqMgDHCfgc3ted66cYnZmkZLfh4R9U0RS';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
