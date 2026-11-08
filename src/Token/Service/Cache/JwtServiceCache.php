<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service\Cache;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use WeakMap;

final class JwtServiceCache
{
    private readonly WeakMap $issuerCache;
    private readonly WeakMap $decryptorCache;
    private ?JwtTokenReissuer $reissuer = null;

    public function __construct()
    {
        $this->issuerCache    = new WeakMap();
        $this->decryptorCache = new WeakMap();
    }

    public function getIssuer(JwtKeyManager $manager): JwtTokenIssuer
    {
        return $this->issuerCache[$manager] ??= new JwtTokenIssuer($manager);
    }

    public function getDecryptor(JwtKeyManager $manager, $validator): JwtTokenDecryptor
    {
        return $this->decryptorCache[$manager]
            ??= new JwtTokenDecryptor($manager, $validator);
    }

    public function getReissuer(): JwtTokenReissuer
    {
        return $this->reissuer ??= new JwtTokenReissuer();
    }
}
