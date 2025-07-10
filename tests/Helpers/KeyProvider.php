<?php

namespace Tests\Helpers;

require_once __DIR__ . '/PemProvider.php';

use Tests\Helpers\PemProvider;

class KeyProvider
{
    private static function createAsymetricKeysItem($algorithm, $dir): array
    {
        return [
            $algorithm => [
                'private' => PemProvider::getPrivateKey($dir),
                'public' => PemProvider::getPublicKey($dir)
            ]
        ];
    }

    private static function createSymmetricKeyItem(string $alg, string $path): array
    {
        return [$alg => ['passphrase' => PemProvider::getPassphrase($path)]];
    }

    public static function getAll(): array
    {

        return array_merge(
            //rs
            self::createAsymetricKeysItem('RS256', 'rsa/2048'),
            self::createAsymetricKeysItem('RS384', 'rsa/3072'),
            self::createAsymetricKeysItem('RS512', 'rsa/4096'),
            //ps
            self::createAsymetricKeysItem('PS256', 'rsa/2048'),
            self::createAsymetricKeysItem('PS384', 'rsa/3072'),
            self::createAsymetricKeysItem('PS512', 'rsa/4096'),
            //rsa
            self::createAsymetricKeysItem('RSA1_5', 'rsa/2048'),
            self::createAsymetricKeysItem('RSA-OAEP', 'rsa/3072'),
            self::createAsymetricKeysItem('RSA-OAEP-256', 'rsa/4096'),
            //ec
            self::createAsymetricKeysItem('ES256', 'ec/prime256v1'),
            self::createAsymetricKeysItem('ES384', 'ec/secp384r1'),
            self::createAsymetricKeysItem('ES512', 'ec/secp521r1'),
            //hmac
            self::createSymmetricKeyItem('HS256', 'hmac/hs256'),
            self::createSymmetricKeyItem('HS384', 'hmac/hs384'),
            self::createSymmetricKeyItem('HS512', 'hmac/hs512'),
        );
    }

    public static function getSupportedAlgorithms(): array
    {
        return array_keys(self::getAll());
    }
}
