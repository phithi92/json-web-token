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
        $token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXUyJ9.eyJleHAiOjIwNDY5NjY0MzgsImF1ZCI6ImxvY2FsaG9zdCIsImlhdCI6MTczMTQzMzYzOH0.W9mNoJIe3gU_96YTFuT5-m-50e2C3FGs5hi8W6EwrROWey0WKgWiF7ZC0Q3yJzTBguoKqzHBF8pyEexLqLNuA_RxQ1FZ3VZtJYSa50Q4SILRenNLILcFA20uzr_GFb_1DXdn6zdxlS00vbEus5xJVJAw1gz7Kh2J-CltqhNQlnq4uZlW32h6FFBdV0bMyxxTHC7d06aqYmD7QLb90A9pn1QGCIaO_t-mLfUdK_uycLe-XdWZUYmeHWIn5JCYfSfTKxXn-rwfPiE7AyGswb1YeJA8y2qbfp8-yAN9g0gonVENGrJNCfk1V9E9K8xoQYnPlbY9Cmj-FTOUHTs0-C46UmTuHf6YPeSFZkyTe3YTRNJEkPE_kXetErI5tb7JczV_btA3baPA1F5QOQ9StaCGrl5vxSM7hQQBIZBSPEpeuo8FJRUebA4oBQb_yTAxosLTCsIzd5El4x9qdnz4QyKaZLgy2qzojZXSaJN4w74wCqdpOwoEP6-PuCfgJI_R8dQzwGWezFNRXj3hQUJudcgGcTGy6PDibOVFzHio7zChIKjNlmXUyzFGgBgPp-Blr4vRe7h2huyqXWBi7k9kuxfkYxoeg8Yc5B_lwbsuupOGR5i-IT9kn89-umJtH5VPx4dbEo2IRv2NaTjFFt0ql2VAG6tFige2zn2PgWdxzYB-3J0';
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
