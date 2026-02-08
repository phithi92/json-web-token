<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\OpenSsl;

use function implode;
use function openssl_error_string;

final class OpenSslErrorHelper
{
    private const MESSAGE_PREFIX = 'OpenSSL error(s):';

    /**
     * @var array<string>
     */
    private array $lastErrors = [];

    /**
     * Clears the OpenSSL error queue.
     */
    public function clearErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }

    /**
     * Collects all OpenSSL errors currently stored in the error queue.
     *
     * Note: This also clears the queue.
     *
     * @return array<string>
     */
    public function collectErrors(): array
    {
        $errors = [];
        $seen   = [];

        while (($error = openssl_error_string()) !== false) {
            if (isset($seen[$error])) {
                continue;
            }

            $seen[$error] = true;
            $errors[] = $error;
        }

        $this->lastErrors = $errors;

        return $errors;
    }

    public function getFormattedErrorMessage(string $prefix = self::MESSAGE_PREFIX): string
    {
        $errors = $this->collectErrors();

        return $errors === []
            ? $prefix . ' <none>'
            : $prefix . ' ' . implode(' | ', $errors);
    }

    public function getLastFormattedErrorMessage(string $prefix = self::MESSAGE_PREFIX): string
    {
        $errors = $this->lastErrors;
        $this->lastErrors = [];

        return $errors === []
            ? $prefix . ' <none>'
            : $prefix . ' ' . implode(' | ', $errors);
    }
}
