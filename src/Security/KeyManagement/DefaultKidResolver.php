<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security\KeyManagement;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function is_string;

final class DefaultKidResolver implements KidResolverInterface
{
    /**
     * Resolve key ID (kid) using the following priority:
     *
     * 1) Header "kid"
     * 2) Config "kid"
     * 3) Deterministic fallback from "alg[.enc]"
     * 4) Single configured key
     *
     * @param array<string, mixed> $config
     */
    public function resolve(JwtBundle $bundle, array $config): string
    {
        $header = $bundle->getHeader();

        // 1) Explicit kid in header
        if ($header->hasKid()) {
            return $header->getKid();
        }

        // 2) alg(.enc) fallback
        $kid = $this->resolveAlgEncFallbackKid($bundle, $config);
        if ($kid !== null) {
            return $kid;
        }

        throw new InvalidFormatException('No "kid" found in bundle or configuration');
    }

    /**
     * Builds a fallback kid as:
     *   "<alg>" or "<alg>.<enc>"
     *
     * Header values are preferred over config values.
     *
     * @param array<string, mixed> $config
     */
    private function resolveAlgEncFallbackKid(JwtBundle $bundle, array $config): ?string
    {
        $header = $bundle->getHeader();

        // Resolve algorithm
        $alg = $header->getAlgorithm()
            ?? (isset($config['alg']) && is_string($config['alg']) ? $config['alg'] : null);

        if (! is_string($alg) || $alg === '') {
            return null;
        }

        // Resolve encryption (optional, mostly JWE)
        $enc = $header->getEnc()
            ?? (isset($config['enc']) && is_string($config['enc']) ? $config['enc'] : null);

        if (is_string($enc) && $enc !== '') {
            return $alg . '.' . $enc;
        }

        return $alg;
    }
}
