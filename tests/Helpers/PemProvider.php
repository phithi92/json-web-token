<?php

namespace Tests\Helpers;

final class PemProvider
{
    private static string $resolvedBasePath;

    private static function getBasePath(): string
    {
        if (isset(self::$resolvedBasePath)) {
            return self::$resolvedBasePath;
        }

        return self::$resolvedBasePath = getenv('KEYS_PATH') ?:
                realpath(__DIR__ . '/../keys');
    }

    public static function getPrivateKey(string $alg): string
    {
        return self::load("{$alg}/private.pem");
    }

    public static function getPublicKey(string $alg): string
    {
        return self::load("{$alg}/public.pem");
    }

    public static function getPassphrase(string $alg): string
    {
        $path = self::getBasePath() . "/{$alg}/secret.key";

        if (!file_exists($path)) {
            throw new \RuntimeException("Passphrase file not found: $path");
        }

        return trim(file_get_contents($path));
    }

    public static function getAll(): array
    {
        $result = [];

        foreach (glob(self::getBasePath() . '/*', GLOB_ONLYDIR) as $algDir) {
            $alg = basename($algDir);

            $result[$alg] = [
                'private'     => self::getPrivateKey($alg),
                'public'      => self::getPublicKey($alg),
                'passphrase'  => self::getPassphrase($alg),
            ];
        }

        return $result;
    }

    private static function load(string $relativePath): string
    {
        $path = self::getBasePath() . '/' . $relativePath;

        if (!file_exists($path)) {
            throw new \RuntimeException("PEM file not found: $path");
        }

        return file_get_contents($path);
    }
}
