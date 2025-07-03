<?php

namespace Phithi92\JsonWebToken;

/**
 * JwtTokenHelper provides utility methods for working with JWT bundles,
 * such as refreshing issued and expiration times.
 */
class JwtTokenHelper
{
    /**
     * Refreshes a JWT token by cloning its header and payload, and updating
     * the "iat" (issued at) and "exp" (expiration) claims.
     *
     * This method does not modify the original token but returns a new instance
     * with updated time-based claims.
     *
     * @param EncryptedJwtBundle $jwtBundle   The existing token bundle to refresh.
     * @param string             $interval A valid strtotime-compatible interval for expiration (e.g., '+1 hour').
     * @return EncryptedJwtBundle          A new bundle with updated time claims.
     */
    public static function refresh(EncryptedJwtBundle $jwtBundle, string $interval): EncryptedJwtBundle
    {
        // Clone header and payload to avoid mutating original token
        $header = clone $jwtBundle->getHeader();
        $payload = clone $jwtBundle->getPayload();

        // Update issued-at to current time and expiration to the specified interval
        $payload
            ->setIssuedAt('now')
            ->setExpiration($interval);

        // Return a new token bundle with updated payload
        return new EncryptedJwtBundle($header, $payload);
    }
}
