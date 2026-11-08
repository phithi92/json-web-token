<?php

namespace Tests\phpbench;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key as FireKey;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PhpBench\Attributes as Bench;

#[Bench\Iterations(10)]
#[Bench\Revs(1000)]
#[Bench\Warmup(2)]
#[Bench\BeforeMethods('setUp')]
final class JwtBench extends BenchmarkBase
{
    private string $secret;
    private array $payload;

    private string $phithiToken;
    private string $firebaseToken;

    private JwtTokenService $jwtService;
    private JwtTokenDecryptor $phithiDecryptor;
    private JwtTokenIssuer $phithiIssuer;

    public function setUp(): void
    {
        $algorithm = 'HS256';

        $manager = new JwtKeyManager();
        $keys = $this->getAllProvidedKeys();

        $manager->addPassphrase($keys[$algorithm]['passphrase'], $algorithm);

        $this->manager = $manager;

        $this->secret = $keys[$algorithm]['passphrase'];
        $this->payload = [
            'sub' => '123',
            'role' => 'admin',
            'iat' => time(),
            'exp' => time() + 3600,
        ];

        $this->jwtService = new JwtTokenService(new JwtValidator());

        $this->phithiDecryptor = new JwtTokenDecryptor($this->manager, new JwtValidator());
        $this->phithiIssuer = new JwtTokenIssuer($this->manager);

        // setup tokens once
        $this->phithiToken = $this->jwtService->createTokenStringFromArray($algorithm, $this->manager, $this->payload);
        $this->firebaseToken = FirebaseJWT::encode($this->payload, $this->secret, $algorithm);
    }

    // --------------------
    // Encode / Sign
    // --------------------

    public function benchPhithiEncode(): void
    {
        $payload = JwtPayloadCodec::decode($this->payload);
        $bundle = $this->phithiIssuer->issue('HS256', $payload);
        JwtBundleCodec::serialize($bundle);
    }

    public function benchFirebaseEncode(): void
    {
        FirebaseJWT::encode($this->payload, $this->secret, 'HS256');
    }

    // --------------------
    // Decode / Verify
    // --------------------

    public function benchPhithiDecode(): void
    {
        $this->phithiDecryptor->decrypt($this->phithiToken);
    }

    public function benchFirebaseDecode(): void
    {
        FirebaseJWT::decode($this->firebaseToken, new FireKey($this->secret, 'HS256'));
    }
}
