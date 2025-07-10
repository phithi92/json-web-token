<?php

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;
use Phithi92\JsonWebToken\JwtTokenParser;
use Phithi92\JsonWebToken\JwtValidator;

require_once __DIR__ . '/../Helpers/KeyProvider.php';

use Tests\Helpers\KeyProvider;

abstract class BenchmarkBase
{
    protected array $cache;

    protected array $supportedAlgorithms;

    private JwtValidator $validator;

    protected JwtAlgorithmManager $manager;

    public function provideAlgs(): array
    {
        $algs = array_keys($this->getAllProvidedKeys());
        return array_combine($algs, array_map(fn($alg) => ['alg' => $alg], $algs));
    }

    protected function getAllProvidedKeys(): array
    {
        if (isset($this->supportedAlgorithms)) {
            return $this->supportedAlgorithms;
        }

        return $this->supportedAlgorithms = KeyProvider::getAll();
    }

    protected function getExpiredToken(string $alg): string
    {
        if (!isset($this->cache['expired'][$alg])) {
            $manager = $this->getManager();
            $payload = (new JwtPayload())->fromArray(
                [
                'iat' => time() - 7200,
                'exp' => time() - 3600,
                ]
            );

            $bundle = JwtTokenFactory::createTokenWithoutValidation($manager, $payload, $alg);
            $token = JwtTokenParser::serialize($bundle);
            $this->cache['expired'][$alg] = $token;
        }

        return $this->cache['expired'][$alg];
    }

    protected function getValidToken(string $alg): string
    {
        if (!isset($this->cache['valid'][$alg]) || is_string($this->cache['valid'][$alg]) === false) {
            $manager = $this->getManager();
            $payload = self::createPayload();

            $additionalPayload = [
                'iat' => time(),
                'exp' => time() + 3600,
            ];
            foreach ($additionalPayload as $key => $value) {
                $payload->addClaim($key, $value);
            }

            $bundle = JwtTokenFactory::createToken($manager, $payload, $alg);

            $token = JwtTokenParser::serialize($bundle);

            $this->cache['valid'][$alg] = $token;
        }

        return $this->cache['valid'][$alg];
    }

    protected function getInvalidToken(string $alg): string
    {
        if (!isset($this->cache['invalid'][$alg])) {
            $valid = $this->getValidToken($alg);
            $parts = explode('.', $valid);

            if (count($parts) === 3) {
                $parts[2] = 'invalidsig';
            } elseif (count($parts) === 5) {
                $parts[1] = 'invalidiv';
                $parts[4] = 'sinvalidsig';
            }

            $token = implode('.', $parts);
            $this->cache['invalid'][$alg] = $token;
        }

        return $this->cache['invalid'][$alg];
    }


    protected function getManager(): JwtAlgorithmManager
    {
        if (isset($this->manager)) {
            return $this->manager;
        }

        $manager = new JwtAlgorithmManager();
        $configArray = $this->getAllProvidedKeys();

        foreach ($configArray as $algorithm => $data) {
            if (isset($data['private'])) {
                $manager->addPrivateKey($data['private'], $algorithm);
            }

            if (isset($data['public'])) {
                $manager->addPublicKey($data['public'], $algorithm);
            }

            if (isset($data['passphrase'])) {
                $manager->addPassphrase($data['passphrase'], $algorithm);
            }
        }

        return $this->manager = $manager;
    }

    protected static function createPayload(): JwtPayload
    {
        return (new JwtPayload())
            ->setIssuer('https://auth.myapp.com')
            ->setAudience(["frontend", "mobile-app"]);
    }

    protected function getValidator(): JwtValidator
    {
        if (isset($this->validator)) {
            return $this->validator;
        }

        return $this->validator = new JwtValidator(
            expectedIssuer: 'https://auth.myapp.com',
            expectedAudience: 'frontend',
        );
    }
}
