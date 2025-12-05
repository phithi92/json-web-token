<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use function implode;
use function openssl_error_string;

final class OpenSslErrorHelper
{
    private const MESSAGE_PREFIX = 'OpenSSL error(s):';

    /**
     * Collects all OpenSSL errors currently stored in the error queue.
     *
     * @return array<string> List of OpenSSL error messages
     */
    public static function collectErrors(): array
    {
        $errors = [];

        while ($error = openssl_error_string()) {
            $errors[] = $error;
        }

        return $errors;
    }

    /**
     * Returns a formatted string with all OpenSSL errors concatenated.
     *
     * @param string $prefix Optional text before the error string
     */
    public static function getFormattedErrorMessage(?string $prefix = self::MESSAGE_PREFIX): string
    {
        $errors = self::collectErrors();

        return $errors === [] ? $prefix . ' <none>' : $prefix . ' ' . implode(' | ', $errors);
    }
}
