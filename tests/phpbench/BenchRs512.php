<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchRs512 extends \BenchmarkBase
{        
    // Benchmarks für die RSA-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('RS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }

    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('RS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.ht5cmagR9eFbcCkdzua-aIAt_gmaeSHCgZ8RLiVelCfbIae_Ri2a_pHYaeUP-TimLDMk99dQ0SGMQrr4_0hjLaMVdYFcjybhOfVCjrrfq5vH8j4cfc_BnwIvQdrFZYessexh2muf1Yx6WraPWkSxvfwLoCjMTNaEg9fvdap8nUwzIG_39TeOgo-eFwbhp4xsWm_1TzBel3_17XPXm8BwB8bdL7kk_A_WGmcxJPPxYC-p3B0lqi323Ek2bq563uW1eOLW3QLnI24wyLo0vnFsNeghBLh-nys6CAXDENbqswWbwk9Gm-vzIcwwMjYIc1eWvSehw6oEDRnGXJJrd5_CLA6Bn_aAaLbgIDPo11sXbX4jKFqBFAegPXWvLt7uBscKHFJTcWkLinwN_JT2ryNuPfZZaNSEADYoH8JADRnhCNj6cmUMIHkLxOD4dLfrnCRCYpuyrdDz7VCA7zh6uPpDW9Q5d0e-JNZ8btLbHC8nFKem9eDiZUvGIMS-XxXhYhyHmc-xkQkqSRrjd6AvsKOH_4bTK1VMPZIbrGqRHWwyAnKoTaJdgbydiupzDMYP17GFDIvL_Mv-9yqhCMvOkuG2xAMwiE4hZjNgBMULCCs0lnKsi9J-6pG1OTvAJaDPQc2QWQkJbKSJyTzE8l8Y2XQPrPBoED-O7d3UG5kJxX1IMTI';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('RS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.w3VoOKEuti7JZuoivl-33IZtbOqoK81XYjyelnH_Zo3Q7P2NOo6kVHpJSkvB4kcHlKpQu4l2-OCxg7QIQqhLjM8e_HiGOIpQjv4rd8tcW6r14EAQPp6Rhhlysoz7ee9ghmrA7rhKMbD8LfMWaYA8rXqgwrp97jZVdMzGZew8g5Y1WjA84ibSWJRtcNvWhxc5a98QyTGs9xt5gg-6vm8WrIcj5ZKHhRnPhXD60nsqBj9EghNiERdEdTUCfl6RNtG9RMqQE2ndv1g0yRfVms1eODvtq95aIJtv6qh-6mY_n1c52f-V2oWfx-bva3PpegzLjCP6JIEJU14Bd4JaDNkm0IM-aYFssT7fi_35hf73kfPk0Aa-K39S6ColhsXHHX5se7CwdhkXrYvcbMVz2J_coGAC2ynWGJeeyQWMc4hPVD8zBvnN4NdVm1qfWtlb5x0TFgrr_f6egiLN61E0pHDphqnEEhOgc9fUFu97bORpauuNCSQpXDH2YuLzL3mOnsCsBJzaq3kC7GENL9bB1nfq8OWJeWTCSSus7YVKlTOKfdflHRHzjijrFc2QuGKx28kGQK5uTqTT1WhxOhgL1fXeDg1JuP_cYALY4WbuId6oryCezcFkznWNmf36LUCnc2lQeBa7K_bk1OF2oQz8eIbItHNN9xanB7fT8OCfwcNs7RI';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('RS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.FBLlX3XdgxPe4TBUMjT1IwPZmQV4Yeub8yoekDtiAyjup6oI4BOa3aWxCAgCqWrzryJx9yzPZaKFeAB0QiLFAbr46TNPicFkHKsfcnqWgxd8_m-z0SPNY13-1Dbrybb7mh3dKZxEed8LAeX2Im2XfarUQkJK-S-Z2MLCMv4ihvALX-9S31_fPzq3wp5metgCvEDYP8KzMr3hsZolbT5hvamrPnAjvhDK5JV-tpI5ow2Oh-Cc4V_ehOMlB0O36OzN7yFoKcWYu1l41p9uKrrJhbo3gJX_Lj0BTqPQoct5bpqG7T6VNA8PMwBVwNefskD_c4qNn5DT8EH_mCyzRBOa7q1_RzlCw39CnWFD7v-lRKV2i2N2JUuaNJ8vMYcpYrEAvBQyLgWQkfndgM9NXSddP_2IEwkbNJ8GjhtSYut9yu9xPTnXJ3edtccbtgIS_k-QkfV3Z6NMcak8vgMYAaiSSvy9bu99UpciFD-bI6hMel9MNjw3IyP44vmAMnk9Gki4EnZCh42rvPPgtiCsmKN_mBNG-v34axtxD3SDkhY5D_qwk9ljJEFV4J_LuBhUmNa3lJ3sp-iZ_exK2L3vIxuh69d0041JbYk31_pqRs5yeFM0KWiy-YUG2MP_dJDLnfYeUT51pO-J6ZQ35rTZk4vqunhTrjr1hv-pZnrjHf5ZAkI';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
