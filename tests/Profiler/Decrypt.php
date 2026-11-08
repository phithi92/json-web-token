<?php

namespace Tests\Profiler;

class Decrypt 
{
    public function benchVerify(array $params): void
    {
        $token = $this->getValidToken($params['alg']);

        $c = new JwtTokenDecryptor($this->getManager());
        $c->decrypt($token);
    }
}
