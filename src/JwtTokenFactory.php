<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

/**
 * Factory class for creating, encrypting, decrypting, and validating JWTs.
 *
 * This class orchestrates the full lifecycle of JSON Web Tokens, including:
 * - Creating JWTs with configurable algorithms and handlers.
 * - Applying and validating encryption, signatures, IVs, and CEKs.
 * - Decrypting and verifying existing tokens based on algorithm configuration.
 * - Delegating responsibilities to pluggable handler interfaces.
 *
 * Acts as a central access point to assemble or parse `EncryptedJwtBundle` objects
 * using a configured `JwtAlgorithmManager` and optional `JwtValidator`.
 */
final class JwtTokenFactory
{
    /**
     * Creates a signed and/or encrypted JWT using the provided payload and algorithm.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager instance.
     * @param JwtPayload $payload Payload object containing JWT claims.
     * @param string $algorithm Algorithm name (e.g., 'RS256').
     * @param JwtValidator|null $validator Optional validator instance.
     * @param string|null $kid Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     */
    public static function createToken(
        JwtAlgorithmManager $manager,
        JwtPayload $payload,
        string $algorithm,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $builder = new JwtTokenBuilder($manager, $validator);
        return $builder->create($payload, $algorithm, $kid);
    }

    /**
     * Creates a JWT from an associative array of claims.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager instance.
     * @param array $claims Associative array of JWT claims.
     * @param string $algorithm Algorithm name.
     * @param JwtValidator|null $validator Optional validator instance.
     * @param string|null $kid Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     */
    public static function createTokenFromArray(
        JwtAlgorithmManager $manager,
        array $claims,
        string $algorithm,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $payload = JwtPayload::fromArray($claims);
        return self::createToken($manager, $payload, $algorithm, $validator, $kid);
    }

    /**
     * ⚠️ SECURITY WARNING:
     * Creates a JWT without performing any validation.
     *
     * This method **bypasses all internal validation checks** and is intended
     * **exclusively** for controlled testing environments, stubbing, or internal tooling.
     *
     * ❌ Do NOT use this method in production code.
     * ❌ It disables signature, claim, and context verification.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager instance.
     * @param JwtPayload $payload JWT payload.
     * @param string $algorithm Algorithm name.
     * @param JwtValidator|null $validator Ignored in this method.
     * @param string|null $kid Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     *
     * @throws \LogicException If used in production context.
     */
    public static function createTokenWithoutValidation(
        JwtAlgorithmManager $manager,
        JwtPayload $payload,
        string $algorithm,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $builder = new JwtTokenBuilder($manager, $validator);
        return $builder->createWithoutValidation($payload, $algorithm, $kid);
    }

    /**
     * Creates a JWT and returns it as a serialized string (JWT compact format).
     *
     * @param JwtAlgorithmManager $manager Algorithm manager instance.
     * @param JwtPayload $payload JWT payload.
     * @param string $algorithm Algorithm name.
     * @param JwtValidator|null $validator Optional validator.
     * @param string|null $kid Optional key ID.
     *
     * @return string JWT as a compact string.
     */
    public static function createTokenString(
        JwtAlgorithmManager $manager,
        JwtPayload $payload,
        string $algorithm,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): string {
        $bundle = self::createToken($manager, $payload, $algorithm, $validator, $kid);
        return JwtTokenParser::serialize($bundle);
    }

    /**
     * Decrypts and validates a JWT string using the provided manager and validator.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager.
     * @param string $jwt Serialized JWT string.
     * @param JwtValidator|null $validator Optional validator.
     *
     * @return EncryptedJwtBundle Decrypted and parsed JWT bundle.
     */
    public static function decryptToken(
        JwtAlgorithmManager $manager,
        string $jwt,
        ?JwtValidator $validator = null
    ): EncryptedJwtBundle {
        $processor = new JwtTokenDecryptor($manager, $validator);
        return $processor->decrypt($jwt);
    }

    /**
     * Decrypts a JWT string without performing validation.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager.
     * @param string $jwt Serialized JWT string.
     * @param JwtValidator|null $validator Ignored in this method.
     *
     * @return EncryptedJwtBundle Decrypted JWT bundle.
     */
    public static function decryptTokenWithoutValidation(
        JwtAlgorithmManager $manager,
        string $jwt,
        ?JwtValidator $validator = null
    ): EncryptedJwtBundle {
        $processor = new JwtTokenDecryptor($manager, $validator);
        return $processor->decryptWithoutValidation($jwt);
    }

    /**
     * Validates a JWT string by decrypting and passing it to a JwtValidator.
     *
     * @param JwtAlgorithmManager $manager Algorithm manager instance.
     * @param string $jwt Serialized JWT string.
     * @param JwtValidator $validator Validator instance.
     *
     * @return bool True if the token is valid, false otherwise.
     */
    public static function validateToken(
        JwtAlgorithmManager $manager,
        string $jwt,
        JwtValidator $validator
    ): bool {
        $processor = new JwtTokenDecryptor($manager, $validator);
        $bundle = $processor->decrypt($jwt);
        return $validator->isValid($bundle->getPayload());
    }

    /**
     * Refreshes a JWT by cloning its payload and updating the timestamps.
     *
     * @param EncryptedJwtBundle $jwtBundle Existing JWT bundle to refresh.
     * @param string $interval Expiration interval (e.g., "+1 hour").
     *
     * @return EncryptedJwtBundle New JWT bundle with refreshed timestamps.
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
