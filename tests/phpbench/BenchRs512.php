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
        $token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.zS6b-po09u99fydti_Ooj_XzvWTAut9eOaR_mxRkSypv7EjUklyiFfbMli3uNXm-vtimAtZGNrOQdjiZZJpIMWKm7CYVRDS_1abbWIN448iDzQ9uzt-5YrFLmmpVJtLYnwZoxRxH49uU6tub_GEoUq07_8lz0T5pP9PkhXPVHQVADywgNRl8VFRMeuBZzmXhnSD8TFzdG2Ga4IZWbw0CiseKjxMgzctdNmD0Gt5MUSRrlVTD1EX-mIfJIG3kj8IP_WCTj7W6wczigQrqDAD2SyoHPz0t-zUKE9gjx3mgC1IvnRoBO9-PVYFOeDeHtVoF7CNBCSTucJQNXQFvox-NbTmuOCSihbgcFXqCbHiMlheJTqdJuSw-VjCfn0vVucRR1OG85DaUR1khZne_KOFdnwCFa-HWpmQJSmYAAi1ljrsPvQtSn2jhjlrncIddPVkAzOoNT5s-O2Z1j9gbNQ-V41mE88tSo0La9L2HmiuxP1hj67rfTVtlQ6JCyTsMAhp5-vE33gT8sHuPsdiKE3V4OzRF1Is8O3m3y_XJOzfpuIT1Spvc2EAO1zq5Z-N9fhekylCgPNBqhLvwEHngPB5p5eX9zNhIu1zgCFAgfgZyk2SqGInLzrl2YAn6cal_cZ-j8XY4xqi37bpO9e2fiyzFLMGJnU00b9GSS_O8bcLomBw';
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
