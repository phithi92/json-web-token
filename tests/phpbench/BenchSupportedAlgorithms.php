<?php

namespace Tests\phpbench;

use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidJwtIdException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJtiValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PhpBench\Attributes as Bench;

use function assert;

#[Bench\Revs(1000)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
#[Bench\ParamProviders('provideAlgs')]
class BenchSupportedAlgorithms extends BenchmarkBase
{
    public function provideAlgs(): array
    {
        $algorithms = parent::provideAlgs();

        $validatorUseAllowList = new JwtValidator(
            jwtIdValidator: new InMemoryJtiValidator(useAllowList: true)
        );

        foreach ($algorithms as &$params) {
            $alg = $params['alg'];

            $params['token'] = $this->getValidToken($alg);
            $params['invalidToken'] = $this->getInvalidToken($alg);
            $params['expiredToken'] = $this->getExpiredToken($alg);
            $params['protectedToken'] = $this->getReplayProtectedToken($alg, $validatorUseAllowList);

            if ($this->getManager()->hasPassphrase($alg)) {
                $params['passphrase'] = $this->getManager()->getPassphrase($alg);
            }

            if ($this->getManager()->hasKey($alg, KeyRole::Public)) {
                $params['public_key'] = $this->getManager()->getKeyMetadata($alg, KeyRole::Public)->pem();
            }

            if ($this->getManager()->hasKey($alg, KeyRole::Private)) {
                $params['private_key'] = $this->getManager()->getKeyMetadata($alg, KeyRole::Private)->pem();
            }
        }

        return $algorithms;
    }

    public function benchSign(array $params): void
    {
        $alg = $params['alg'];

        $manager = $this->getManager();
        $issuer = new JwtTokenIssuer($manager);

        $payload = JwtPayloadCodec::decode(['role' => 'admin']);
        $bundle = $issuer->issue($alg, $payload);
        JwtBundleCodec::serialize($bundle);
    }

    public function benchVerify(array $params): void
    {
        $token = $params['token'];
        $manager = $this->getManager();
        $decryptor = new JwtTokenDecryptor($manager, new JwtValidator());

        $decryptor->decrypt($token);
    }

    public function benchExpired(array $params): void
    {
        $token = $params['expiredToken'];
        $manager = $this->getManager();
        $decryptor = new JwtTokenDecryptor($manager, new JwtValidator());


        try {
            $decryptor->decrypt($token);
        } catch (PayloadException $e) {
            assert($e instanceof ExpiredPayloadException);
        }
    }

    public function benchInvalid(array $params): void
    {
        $token = $params['invalidToken'];
        $manager = $this->getManager();
        $decryptor = new JwtTokenDecryptor($manager, new JwtValidator());


        try {
            $decryptor->decrypt($token);
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
        $token = $params['protectedToken'];
        $manager = $this->getManager();

        $validator = $this->createReplayValidator();

        $decryptor = new JwtTokenDecryptor($manager, $validator);


        $bundle = $decryptor->decrypt($token);
        $this->denyBundle($bundle, $validator);

        try {
            $decryptor->decrypt($token);
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
