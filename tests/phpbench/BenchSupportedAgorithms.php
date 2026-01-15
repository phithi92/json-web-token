<?php

namespace Tests\phpbench;

use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use PhpBench\Attributes as Bench;

use function assert;

#[Bench\Revs(1000)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
#[Bench\ParamProviders('provideAlgs')]
class BenchSupportedAgorithms extends BenchmarkBase
{
    public function benchCreate(array $params): void
    {
        $this->getValidToken($params['alg']);
    }

    public function benchVerify(array $params): void
    {
        $token = $this->getValidToken($params['alg']);

        $c = new JwtTokenDecryptor($this->getManager());
        $c->decrypt($token);
    }

    public function benchExpired(array $params): void
    {
        $token = $this->getExpiredToken($params['alg']);

        try {
            $c = new JwtTokenDecryptor($this->getManager());
            $c->decrypt($token);
        } catch (PayloadException $e) {
            assert($e instanceof ExpiredPayloadException);
        }
    }

    public function benchInvalid(array $params): void
    {
        $token = $this->getInvalidToken($params['alg']);

        try {
            $c = new JwtTokenDecryptor($this->getManager());
            $c->decrypt($token);
        } catch (TokenException $e) {
            assert($e instanceof TokenException);
        }
    }
}
