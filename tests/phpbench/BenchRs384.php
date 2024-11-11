<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchRs384 extends \BenchmarkBase
{        
    // Benchmarks für die HMAC-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('RS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }
    
    // Benchmarks für die HMAC-Algorithmen
    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('RS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.Goeb-6utGsCo136qEazHhtNv5scY3HFLNPyPwDL-q7-WOioDhVckSbN5JVD3pqSa59nAdr3FHTD_5QuMvydJpFTyGZdFCRrqDA6kN6yi_jJSycRPyfM_lklz9elCrFyZJfekEyMGh2rtzohs-tk3TZQ8BpOrtPClJe__6nDZQZAIMbE6kfqzkL85dTK1XSNR6LDRXq3cET8PkDjT4rDFjm7cFvIHIjd0gERUqJ04zCoAiRSWTgg5gf3Gussth_OjC9V0WcQlrb69pgbG1T1d1cwB-7Yk4Vhv5_qfsV3WhAWAXX6pm3LXMHoruok_hlCqT0CL7eRRQsrmYlnKcJbiAlTv6mYv8JqJR1nAPT21yxVDFZiehEcz7zL9cSpT0k51EFjR334mK4DgxHxuKiQSfnpUrqqfN6m6brdiHYqTQ91mHhi46UhtfsaHfGyJ0YqT_dKoCjcdhsfvz8PhkBWm5lvebbiGmlxKfgYvKqfBWnzfIX7Awbr3PuzscWm3uzmq';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('RS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.CDvNVkv6g5lFk94AxFBOmfD2mgY-zYeFOOMMhTSBRcm2hfkKF_GNg0cZBEMUZINhYboniR82wYChksAlB62l7bErpKZV3CRU-tnZ5pm7a6OSAgBVPO7yHxQKn37nGO9e0oz0flZoCfNxWUONA10p-1WwrcerbyjaLptsWe02cbf5xUZkWcBIHRPK-mFBnOxrVnC-O1txzc-AM8U2miSbSsPXrihT5vJZhPyLv789bqZOz8WDyAH_6u4MOqcuA5mswU6b9JY3ih9SxNkw9BP7Ai74nYsoem1vkbCODklqvZDQjeJRvnGs8fDNQyU6gG4ZThZ8hAOsixJCWP8rDTohBAGDJybNHYs_NneAypMs5YrmuY2kQeCnih3CFG_lJjpmTfxP7rlcUIAUzHl950kREu_4yk5ZFDx9UE9Hn7kNujxfUB1enyzK4RxySkob1xuB96TzPCH9pkWDJBDbnXLGAK3zjTLKnHPWZHeV78x4G1zZNtBnNXRjY2AD2MAhR3jr';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('RS384', null, $this->getPem('private',3072),$this->getPem('public',3072));
        $token = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.chxmH38acdPo5Penea19wGyIkD5KmmA-CWjH6Yvzqa7V-Y1NPiIFrWqdbX-pJYBDBkanMFxaHT6QS5yKGCKw0Eyqs2Rwrw8FQpMV_Q-b8i8iO-D1yZVXNGWzVPGkoeOkB5aPN2QOrD3-LEpiYEc7qOaYcXawJt0qNk2Vvs1qa6VrQgSeu6rbJb6d5_2XH44oUA0Gxl6J5Y5cTsUrXhZ5GeKbN0r_9E0NCLy40y88zzMZfdC5OJjbwX4iuZZQesDz27bemW_6MNmvykCf35iGv0AkXaKXzSjCS0NWfkwsb9Kj2yBGh9IiIeFrA6HQ4Y3KsXMAEbcXBUZIEd5fH_R5Fzqw5cAZOcO4jSbMe2BJAfyHaFKDOxVvzE-cVoLVO7eXEegWXJbr5lnZybUQMQxWK1T-1herpBo4IQpCjxjIWPwYZhgCckppSDwojNLPfb5FHoJjAoKtuVSWWlZdvU9Wz261h2UcWlYfynzPFMp2kD5frxXAaUXGZOvmxU3XIvFC';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
