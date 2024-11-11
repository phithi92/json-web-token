<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchEs512 extends \BenchmarkBase
{
    // Benchmarks für die RSA-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('ES512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }

    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('ES512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.sXqEegKlyaHpY0G6eXwzCN9Fy5Ygi85oR6s6578J-gNaFysfLrfTmevmAM5gNM9EVivHHY1_EnBurXloGN8669QhDaCAFtzu6TejmKAtRjBRwFX3D681Ib5U5s8qTuGfCPiF4hJzIrfRqax4Ox7q9-3OxIAk5FvfAaYjjskcBXtiIqgYhp7Nl18HMFWSpEjkTlZGdm4K1mjhsw0AGY9m-N2KN2TwWH1_3prtWgwgjsLFMzP3avZV14lKfcLJmhLf0U1IQVCTeDAvYe6zNHg0lrdI29fb8gMFjr2_HdoFZAvOhhTxbgH23YWL45_nZrI3MfDb89OrxZfjnu2OO9qL0VDbpzjpFZuNHMHkPNrqN0mW5fzjLf13D42vBUGSGx_1CZZEaRlp-lkjWTRcz6Ih2i1p53fotWORzEWxcQI5aTxIICIXhZWgQ6rZegENdlgfDmT2pGuYhGINdfTxNQRUBlKgNKqp0k0O5wvQ4T8TCsLXB5Pq-wjmXeIgco4zCaAGepDYivuXamn5NUR3JFHIrkZ7PSlAlrUzJcbgKW-anWDq12EC12KFV1NyPCKDILL07C71XHaoGkss7Th2-WEAWT_iZItHR6g7dtuExQfA_pLWTkG6M27wnVnCrrgWDviMFn_EzYP-R3mwsE1pnALp8SGPZL15th2qjfGD60oWYB0';
        JwtTokenFactory::decryptToken($manager, $token);
    }    // Benchmarks für die HMAC-Algorithmen
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('ES512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.l-Z-UrqVeYU181o2reeBNMwJqlxQl7rk2lVTKGCilBi6wE8GYRPqgmcEHBVDcXZHx1cAf9ifAXsD_shJh7psxkvr7YGsD-bHdiDykOV7k11aNGj1lzuSQdN1y23gGI00WGS7X-CsfaXhgPo0Gb7TBWgmB3R18ztjF0VjJYk-zG5HFkWRhho-wQOWsOxJu-1Fz2P-3XuU79EszKmd68GpUb3XKkCFa-MDMPTJJuI9Q5FXgMtkcY1HbsROOuXH9gCxV203irSeJ3eEH8aUbeQ1Kc7WApZf2OuulKSlsUrFcUKMSDkcMO9YHsiuJmRFg0J4qwqnACmEyEeT1ts3yaiKo-e2bDb9LjpZfLP9CNHQ0YFn--mavejQnrDVw7RUyT29BlEqlPfxoCZlPc4VHooe-AOhrPu1b_LaAS1trnD_eFJ_AxUa_9ragj-kid8okm5NEbAaWRNDZ-GGCYs_B3udAqnkmLR1e-uQuf34gRwMasvo9LpLTVg-mHGgCo8EglhXzNfHTwVlgPMla0YX9X3DrN9SZxcxcX8RPwNo8Z8j5Z22zPnR2guk_8hL2F0TcQ2SqB5C3iU67ZAl8TqJvPlx191NDIAbVKmyGbD7Z7QUBhA_H41pgY4GXk1ahuGlNlPj78zPB8qrPPziqT1_3RwImrb-K3shhGRVHNeN-yvVy1Y';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('ES512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.pv7MK76-JknylffcYtRemUuDJK4pd0ha5aZqwpwk1a2RjAylsvylvh-UTWa76nWFWB_ZNhKDeMS3EHiwZiWsApktozhuCMwCh8TH925Hp8DoKpuxjOaLZ39SSedvbY5zRd65_YrJOomIao7fkEx7VC0Gc2Hvdbf0Urvhkl2GRwGPccj7XX_axlCqfoq0gZKhqXBPr525ROlMYyT3GIeLNHW7acucuaxaEzMDGWh4nUiN2ZGjyzyunyGtR3ShaxgBY-wf9eB50ujpQ38iRiehXuxi3Tr9nr3XLw2m6hV9czowqZLlwFrXb_98aq_J-o9dat9nLATDCODY0elomnYqIQwC1zLsdFHkdXZ2iSqb2wGTTNZQfThGlcg_2e9n3Igedv9CRDsVNrh7v1VJcQzx5l36iPonl6zHz7KQdGcqKlX4yRA104D_UyXyM7zPYU8m1i098tSBfd3aVV81Blo7ex8K1iwIzghc7VYbjJOysIDTLZqzaGqoQWg4ui0zP_edw0aLxoShbQHdSImSTj50-hugj8VT7MgykbEXOSuJUlUNwv9gY_ru0-BYxocIUrE6Ww4ALa2Hf9vjsNVgHXV9wmtlBO_vAeSIvogLVffZJZUoMMhMvRoPZc-_Z-76jLrlqfpdHv_Niyq3dxA0NUg0YWaTf-_fTpPW5ovdudLDOF8';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
