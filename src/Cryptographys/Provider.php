<?php

namespace Phithi92\JsonWebToken\Cryptographys;

use Phithi92\JsonWebToken\Cryptographys\ProdviderInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use OpenSSLAsymmetricKey;

abstract class Provider implements ProdviderInterface
{
    // The passphrase for symmetric algorithms (optional)
    private readonly ?string $passphrase;

    // The public key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $publicKey;

    // The private key for asymmetric algorithms (optional)
    private readonly ?OpenSSLAsymmetricKey $privateKey;

    public function __construct(JwtAlgorithmManager $manager)
    {
        if ($manager->getPublicKey() === null) {
            $this->passphrase = $manager->getPassphrase();
        } else {
            $this->publicKey = $manager->getPublicKey();
            $this->privateKey = $manager->getPrivateKey();
        }
    }

    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }

    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        return $this->publicKey;
    }

    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }
}