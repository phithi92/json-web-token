<?php

namespace Tests\Helpers;

final class TokenStorage
{
    private const BASE_DIR = __DIR__ . '/../.tmp_tokens';

    public static function write(string $algorithm, string $token, string $key = ''): void
    {
        self::ensureDirectoryExists();
        $path = self::getPath($algorithm, $key);
        if (file_put_contents($path, $token) === false) {
            throw new \RuntimeException("Failed to write token to [$path].");
        }
    }

    public static function read(string $algorithm, string $key = ''): string
    {
        $path = self::getPath($algorithm, $key);
        if (!is_file($path)) {
            throw new \RuntimeException("Token for [$algorithm/$key] not found.");
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException("Failed to read token from [$path].");
        }

        return $content;
    }

    public static function cleanup(): void
    {
        if (!is_dir(self::BASE_DIR)) {
            return;
        }

        $files = glob(self::BASE_DIR . '/token_*.jwt') ?: [];
        foreach ($files as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }

        @rmdir(self::BASE_DIR);
    }

    private static function getPath(string $algorithm, string $key = ''): string
    {
        $safeAlg = preg_replace('/[^a-zA-Z0-9_]/', '_', $algorithm);
        $safeKey = $key !== '' ? '_' . preg_replace('/[^a-zA-Z0-9_]/', '_', $key) : '';
        return self::BASE_DIR . "/token_{$safeAlg}{$safeKey}.jwt";
    }

    private static function ensureDirectoryExists(): void
    {
        if (!is_dir(self::BASE_DIR)) {
            if (!mkdir(self::BASE_DIR, 0777, true) && !is_dir(self::BASE_DIR)) {
                throw new \RuntimeException("Failed to create directory [" . self::BASE_DIR . "]");
            }
        }
    }
}
