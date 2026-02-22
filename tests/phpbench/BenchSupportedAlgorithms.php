<?php

namespace Tests\phpbench;

use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidJwtIdException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PhpBench\Attributes as Bench;

use function assert;

#[Bench\Revs(1000)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
#[Bench\ParamProviders('provideAlgs')]
class BenchSupportedAlgorithms extends BenchmarkBase
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

            if (
                ! $e instanceof MalformedTokenException &&
                ! $e instanceof InvalidTokenException
            ) {
                throw $e;
            }
        }
    }

    public function benchReplayProtected(array $params): void
    {
        $validator = $this->createReplayValidator();
        $c = new JwtTokenDecryptor($this->getManager());
        $token = $this->getReplayProtectedToken($params['alg'], $validator);

        $bundle = $c->decrypt($token, $validator);
        $this->denyBundle($bundle, $validator);

        try {
            $c->decrypt($token, $validator);
        } catch (InvalidJwtIdException $e) {
            assert($e instanceof InvalidJwtIdException);
        }
    }

    private function denyBundle(JwtBundle $bundle, JwtValidator $validator): void
    {
        $exp = $bundle->getPayload()->getExpiration();

        $ttl = (int) $exp;
        if ($ttl <= 0) {
            return;
        }

        $jwtId = new JwtIdInput($bundle->getPayload()->getJwtId());

        $validator->getJwtIdValidator()?->deny($jwtId, $ttl);
    }
}
