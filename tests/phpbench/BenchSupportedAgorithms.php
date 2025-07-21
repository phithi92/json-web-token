<?php

require_once __DIR__ . '/BenchmarkBase.php';

use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use PhpBench\Attributes as Bench;

#[Bench\Revs(1000)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
#[Bench\ParamProviders('provideAlgs')]
class BenchSupportedAgorithms extends BenchmarkBase
{
    public function bench_create(array $params): void
    {
        $this->getValidToken($params['alg']);
    }

    public function bench_verify(array $params): void
    {
        $token = $this->getValidToken($params['alg']);

        JwtTokenFactory::decryptToken($this->getManager(), $token);
    }

    public function bench_expired(array $params): void
    {
        $token = $this->getExpiredToken($params['alg']);

        try {
            JwtTokenFactory::decryptToken($this->getManager(), $token);
        } catch (ExpiredPayloadException) {
        }
    }

    public function bench_invalid(array $params): void
    {
        $token = $this->getInvalidToken($params['alg']);

        try {
            JwtTokenFactory::decryptToken($this->getManager(), $token);
        } catch (TokenException) {
        }
    }
}
