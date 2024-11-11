<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchRSA extends \BenchmarkBase
{
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('RSA-OAEP', null, $this->getPem('private',2048),$this->getPem('public',2048));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('RSA-OAEP', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSU0EtT0FFUCIsInR5cCI6IkpXRSJ9..eDtgUoViwIUVgDsJ0zYTdTYgOl-cAehMpjaAsrEAgR7viNVIVnaMuqNXfrICj_4Nr11JXf5zJs2GcFj6IHECz3JsXKHCUPwVe3FHnBN4R6i9CSoNMFRGlG7phIDB4jfchxA2DgjdSK5SxNTSt7flwmUKJtoxZs4fPj8UzMu9SXQI7Wg5cpkNHpmV2zpLJXQYNDNOU2EcBDlcy3q6JCFrCfxVECImJmnYOfnq8ePVDErjXzRoeWvUj-G2sXErz0FWy1Ovusw7O6dTz0UFvRPyKLppsZ_OmjTCXZooHO-eCanZqxRYFWZ4mgdaJbJ6oQ1BfxjkN-7_L7jqMht607zeNg.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.saFeWsb3DlCtT-ZQ2BmA4hgBspBO7FgNaXQmEgkQHWITggoNhdWFaoi0cxbx9RdBelU8liFc51rNtvO3RQEWj3sjdYtdkO7RYZvj8brYkC5ZDsCoZOkU5GQ2hXl28qaSDUZWR-6L3taDFnymajPMTpngk0oHNTYzMufYMue5HY74Lja-DfXD8m8RGyLZsSBhsGMIdVu_GlKkRZg1XXqmuoeclR44KnZBXSrbGCM63dYJVeod39BGpGmuR3Dg3kvKmcAE9RAlbNFo35jnKC9ScXe6ipFYEIrDxRQEzsyo8gxP44_4fP3R7GvUOpWOiTEsqLGycjk6OXtOhGmFnIIuMg';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('RSA-OAEP', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSU0EtT0FFUCIsInR5cCI6IkpXRSJ9..eWAV0AEuEx-51RI7vpxgtzps9ZeUUQGKmeUavBH3mYXGmszmjN6W4MatAxuYGZI2u8hs_y_AQPHqlyd8QS1d9oumywhSd6N25MWzEuIcl8TStI8NSfzmedjdDgr-8kZMWigDLTG0WdEH3-_TuY6YYrtIzCshZIV3CEQ-gnvLr48sP7xkBWF_Uzlv_-V2HXKhirUiTkea2hzl3V6h1-eFf_x1VQajm6lOiqTNbK34iWh_jPCAi3WoouTZjrOB-3BTKOYOqxmbn1ZDxJ3LtkTL5LT77TPSyr3d0f7EMrGb5v6tU06ygQeEasma2wmv2m3Kmm9XQemFpmPjnHxzwXaDZg.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.JtzEHc88pQvFLJ5TDtJ0d3jCrzvgipN6rhhamqG4tKIhuiMd-ATP8DoOds0z0Y2cB0QsL__aXdFz3CkS6gxvqLoVN180wPDP-KxSnvyBgrwzhbenrXd_oc6HSER0DZLVdPu--seO69FE68LvPecZZ2tb2znnKqwZOGLtFZjYE83PPAt6GcFNWtM4xU2E6FTjCu9RW6s0q6LF5r5Xegj6K0SbOcRVwiwx_1s9c_r_hAYUa2GxDZaz-UhewSIV3DxHZl6ThhhHL6tRdUIbIX-_jAHBFhl5DYCz1Wzojr3V4GLcDXJE-2HN0AWWoqZSFCxucalJj6iOHOuLpwtSNk8yZA';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('RSA-OAEP', null, $this->getPem('private',2048),$this->getPem('public',2048));
        $token = 'eyJhbGciOiJSU0EtT0FFUCIsInR5cCI6IkpXRSJ9..GKrY8Xr3uWZBsuF91QtwI-Wz9ZvemvMdlgofutYKJUo6Eg4qzbD4_gegxI3VhMnQby9QEIU3PuFf2U1RlBo1QwKHFOQxthQcaZpsU-mc16mwqDZ7yGyF8IBzayQCdF_3hEIt-8OnN-hy6vW5iuxnUjv55TmaC-GsSB7LvxbvRlNiLjjuYi6Za6mPE2poadwCp2iZujvo6ecvlJkwyBQ_ewE_ezR6LvhwWWEenkeqf5Dc545y_8_1XDOVCwtYNZwr1EZRZzq0_8-OMTbL36apslGkgIWsB_sLdymwBCJoKPdDm9ECQhoYhSnymuLj-ksGBs8jewfUDbc3hrMt-0hQmA.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.AbfV7I1Br2SWKDQgqSSfcj0Dz7T1J6FJajZSnQ1UAbtLbCy6PhBZfd9L5WyZxx7HQnclzKpEsNQsz0FtVxPocZiX2dp4dGn6JAZ1VAwrpSraeNqa6pK-GG7zlTBbeWRhFQ0ywvYNauYjoCS7nofyBdRdYPPNKR7WxBtJcwf4RoWGy4TH_cQ72gcLZ_x9oIhn011Z6sBCOnt7RaGESngIMfy2AA_wMwd4IUGxPaKHHuCuc0nzZ0Ohz3BwmQ2dNbytXVIMh-uKHFQbBX0HhqXi7p2HjBITp3GZaSFGymoJTZc4lQ56SPtUf8D6yr41FEWZK-yZPmgYjob1EEmPua1HkQ';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
