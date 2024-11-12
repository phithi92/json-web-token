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
        $token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.Vnsk0pmWecvUHiHbEZyNDvuCl8xg9WJLj0l83u95MOJj_jm6YZrEHHTwWZAlrYkTgoDg70Se5q8i-zFjylK90BxbK2YJmQISv-eOZfRxdgZg7_d7YgWNZ8MrR65MXzchOTx3ieO0GuRoF4ZEqJaANtLrBkxQ_rrDMDs2N1a-KvK3vV_F8FVUGof8Q-tYX8bzabZtwADjZqdbS65qxNxP9IBHsC4E5mdQrwiMBLYwQjEPnESA0VYElsvp3j2tbPemzse4cX7PDY0ZW4ZJvU8b9dc9D49jhJm8LFKqKcKfQ4UmsIXbvDnVB17Wc_shymb9tSgp4-u57Ni0EnV9_KOfT73uNHPxMwLNJ8L31IiLoSIvZV-mwqm-RdgHaTnLDUUUTmKRwnrKJLCYm_RgWmStFgzt1QNXRnBhflIq5pXi5klcz2ZDDhJnSCgDHVipPO4yb6Qq6SsrQB-tCb7ecehawAU1JssKS2CzQ1R2rBCx20nogKqxLgYU0erMUmKoRN1zfOWfNHAFIjhzEJJgZaA3zFMU6sOb0F_RMlutz0T-6BhK2XBgk4WrzshilpL7ZVz0xgmPOIHQgdeQVaE5Ud-XR0ujiPao-9Foz94mdQIsd-Z9ELzEIWQsrVoa4SfNDL_EAn7VrSBqJYCMSUdkhF6TufWqVwR681vNxAliuv4HRLQ';
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
