<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoloader von Composer laden
require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;

/**
 * @Revs(1000)       // 1000 Wiederholungen pro Iteration
 * @Iterations(5)    // 5 Iterationen pro Benchmark
 * @Warmup(1)        // 1 Aufwärmrunde
 */
class BenchPs512 extends \BenchmarkBase
{        
    // Benchmarks für die RSA-Algorithmen
    public function bench_create_token()
    {
        $manager = self::setupAlgorithmManager('PS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        JwtTokenFactory::createToken($manager, self::createPayload());
    }

    public function bench_verify_token()
    {
        $manager = self::setupAlgorithmManager('PS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzMzU5NDcsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzMzU5NDcifQ.InTvyalzifl7n7isEpY83fro6LuuLe-9nI3zF8ZQNOjPsi4HKSbVb6KVWF2GX4oOsOBemDnJNE49B9_hXhIJRmvF8mFEfwpWeH-XIWJ5gm3EpmwLoDV5FaHf0SlYIGkcfn3TuXmuCAwWFVyZTin30ciN6ygb_pKlYXH4Eqh2AVizDCYOCKVjUGiwbodMLi5iWB9JQDaYkxrVtckmfSf54np_YJPnXBPtmStbr7ALjpB3kGMx5-QCIBZr1LLFNlOXLotKc6bunR-_ljxxtOKKVzfsHMvJyuNoUpIAA3o_LVQse2ub5onZfKPbAAvhERNW6MUzMo4FXkp9K8VXpvSWPEb8b1d_WIdAvISlL9sEgdcBk1oU7_cTsO4aoOnEq--ifCOtODd_QTs2QsC_YKLrKFoB1gcniCLdB6hY9OjJjtuKBiaKzXr1OyJt1VtFOtfK0DL-Hq5ulUNyqHYJH-y3KMQLDi4htHVV_OskYiZgJkwCU5GQicr6BarFPMcsquKPjm329plSK2dBkinXFyft2-pdL8YSAveJbldTNYsvlr728jUpT0AS_qN10rz6IKkWOajE8Y1fRD338v5mlgnvkdqH0f5fWmNSts3b8mc5MrMRZhsRL9Mum6zDAGfe7-Y9L4iQbos-8ml2YXTz5-dg6PGHIirMox15mqJsB-fAIOY';
        JwtTokenFactory::decryptToken($manager, $token);
    }
    
    public function bench_expired_token()
    {
        $manager = self::setupAlgorithmManager('PS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjE3MzEzMjE2ODAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjE3MzEzMjE2ODAifQ.op7dyTs02aWCBaYDWEPr8sE2JArOMYYrRdnBKQc2ntbYWMI6PjL63nFg90ED-VmQDi0wz7aO47CW1jsTmKgoh_F7Ogh2yph74QC_96l7OqEgN8v_yY-eNqm1vuhWWiK0ina2keC2T2ZV1uq344PmmwjflodSEmMc5ZlnCz_OXnvp75k8BR0fdTF3MRGhxBAeTkQnjxfbL7PRY0e1VEGyJZXxfRLu804GnHYHX2mDhbLf5JPLagZtuB1o9psw4d5wuibph7V64dhqQLKe-ll1GMeNjSt_zX2MpQmA7j5IMM1Qxzpf662GLKBQd6HSkutPNsKmaHfYZ9oZE39nCUdjvYzQ853OOmi0kcSuGgwNnxne4_S5pisYsvZgeviLY_euu11zTpVAgijeAQmpoMw7qsYbRQByMFLepmLxTruldbTPoW6xT6HGrgL5um-R2tDDF755-ksKcGBd7mDz88qXDk-jpsw8rLtnZ04J3acWdO9D75hm-af4uWriwNq6KuCtYcgqH0QqdyJeZQpKv4tcdc39yo_8WxIrlhjl6dEU6d_L5aUT10hhYvB0zUUyrTFTvzG--qDb8SciUid5DD-iVgWw1uI_E2KrnLmHTpantQ4T_4zEWxyWr1wokDfhclGfRxFRuDHt8TAtq5iBtkb-Sj3hXp4clfHKSHUgGwosVd0';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Payload\PayloadException){
            
        }
    }
    
    public function bench_invalid_token()
    {
        $manager = self::setupAlgorithmManager('PS512', null, $this->getPem('private',4096),$this->getPem('public',4096));
        $token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXUyIsImVuYyI6IiJ9.eyJleHAiOjQ4NTUzNzQ2MjAsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6IjQ4NTUzNzQ2MjAifQ.f6jeNbYPwKHbgyHxiGq_oNSb3NvQzjS9AclxVm4Hjpi9ho8BUtEsff5cek7Uy6rw3vrJUN7SVPjR4RlVJhe6N-XG8HZToVjXlcuYGxYhED-w8DZ_ucH5EJPJ7w_XG-Q_VZ6MmLNItfhz5kXa-46l4-7XZolVFhDKafhCnQIEuTiKiRDxGCNQyej_8imuORXjgc8ouVgHCwGxSVs0OuzN0cZP_NdRHxHKPfAKGnzJRjthNvHKzDLIims0Jivo5LRitvWInYZSUPc3y25eAvajbd5hHCfEgXkEGo6C9Zg--q04K5r2gNq16_ERR2snrhuXzqZiqizWl7kAjUh1OowevhoGLh-KBuwvrIq_u6KKkoMnAQ_OQ5V9DpFmUFbaxlAcZtcaCybB46pFOtfrBaronrfdpcRHf4zTkqami74RW_4tggdHqRaKc8_n-dQ1SzggCGpecPzx-P2DUTjI7JMyqciAlhf2wLl3bcFRN_BQMA2dUMApcIS0Pca5DGvRmnoKJW7FOA8tppSv9E9EWW3BudClJzZ_fWp4CSEZpPSj5nviICUo9zzD_vktGf4Cl-nKIkodzHP095cK1LVmp6U6AjX_GeCIUQ-Du2UpwKkGCl5wOwBV4KVIL3MfcA5nEprD1QdliSjnrQD9_W7RzIVN1cB1RVuGsuF48r799wKEQoI';
        try {
            JwtTokenFactory::decryptToken($manager, $token);
        } catch(Phithi92\JsonWebToken\Exceptions\Token\TokenException){
            
        }
    }
}
