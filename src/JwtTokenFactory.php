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
     * @param string              $algorithm Algorithm name (e.g., 'RS256').
     * @param JwtAlgorithmManager $manager   Algorithm manager instance.
     * @param JwtPayload|null     $payload   Optional Payload object containing JWT claims.
     * @param JwtValidator|null   $validator Optional validator instance.
     * @param string|null         $kid       Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     */
    public static function createToken(
        string $algorithm,
        JwtAlgorithmManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $validator ??= new JwtValidator();

        $builder = new JwtTokenBuilder($manager);
        return $builder->create($algorithm, $payload, $kid);
    }

    /**
     * Creates a JWT from an associative array of claims.
     *
     * @param string               $algorithm Algorithm name.
     * @param JwtAlgorithmManager  $manager   Algorithm manager instance.
     * @param array<string,string> $claims    Associative array of JWT claims.
     * @param JwtValidator|null    $validator Optional validator instance.
     * @param string|null          $kid       Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     */
    public static function createTokenFromArray(
        string $algorithm,
        JwtAlgorithmManager $manager,
        array $claims,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $payload = JwtPayload::fromArray($claims);
        return self::createToken($algorithm, $manager, $payload, $validator, $kid);
    }
    
    /**
     * ⚠️ SECURITY WARNING:
     * Creates a JWT without performing any claim validation.
     *
     * This method **bypasses all internal claim validation checks** and is intended
     * **exclusively** for controlled testing environments, stubbing, or internal tooling.
     *
     * @param string              $algorithm Algorithm name.
     * @param JwtAlgorithmManager $manager   Algorithm manager instance.
     * @param JwtPayload|null     $payload   Optional JWT payload.
     * @param string|null         $kid       Optional key ID.
     *
     * @return EncryptedJwtBundle Resulting token bundle.
     *
     * @throws \LogicException If used in production context.
     */
    public static function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtAlgorithmManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $builder = new JwtTokenBuilder($manager);
        return $builder->createWithoutValidation($algorithm, $payload, $kid);
    }

    /**
     * Creates a JWT and returns it as a serialized string (JWT compact format).
     *
     * @param string              $algorithm Algorithm name.
     * @param JwtAlgorithmManager $manager   Algorithm manager instance.
     * @param JwtPayload|null     $payload   Optional JWT payload.
     * @param JwtValidator|null   $validator Optional validator.
     * @param string|null         $kid       Optional key ID.
     *
     * @return string JWT as a compact string.
     */
    public static function createTokenString(
        string $algorithm,
        JwtAlgorithmManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null
    ): string {
        $bundle = self::createToken($algorithm, $manager, $payload, $validator, $kid);
        return JwtTokenParser::serialize($bundle);
    }

    /**
     * Decrypts and validates a JWT string using the provided manager and validator.
     *
     * @param string              $token       Serialized JWT string.
     * @param JwtAlgorithmManager $manager   Algorithm manager.
     * @param JwtValidator|null   $validator Optional validator.
     *
     * @return EncryptedJwtBundle Decrypted and parsed JWT bundle.
     */
    public static function decryptToken(
        string $token,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ): EncryptedJwtBundle {
        $processor = new JwtTokenDecryptor($manager, $validator);
        return $processor->decrypt($token);
    }

    /**
     * Decrypts a JWT string without performing validation.
     *
     * @param string              $token       Serialized JWT string.
     * @param JwtAlgorithmManager $manager   Algorithm manager.
     *
     * @return EncryptedJwtBundle Decrypted JWT bundle.
     */
    public static function decryptTokenWithoutValidation(
        string $token,
        JwtAlgorithmManager $manager
    ): EncryptedJwtBundle {
        $processor = new JwtTokenDecryptor($manager);
        return $processor->decryptWithoutValidation($token);
    }

    /**
     * Validates a JWT string by decrypting and passing it to a JwtValidator.
     *
     * @param string              $token       Serialized JWT string.
     * @param JwtAlgorithmManager $manager   Algorithm manager instance.
     * @param JwtValidator        $validator Validator instance.
     *
     * @return bool True if the token is valid, false otherwise.
     */
    public static function validateToken(
        string $token,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ): bool {
        $validator ??= new JwtValidator();
        $processor = new JwtTokenDecryptor($manager, $validator);
        $bundle = $processor->decrypt($token);
        return $validator->isValid($bundle->getPayload());
    }
    
    public static function refreshTokenFromString(
        string $token,
        string $interval,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ){
        $bundle = JwtTokenParser::parse($token);
        
        self::refreshTokenFromBundle($interval, $bundle, $manager, $validator);
    }

    /**
     * Refreshes a JWT by cloning its payload and updating the timestamps.
     *
     * @param string              $interval  Expiration interval (e.g., "+1 hour").
     * @param EncryptedJwtBundle  $bundle    Existing JWT bundle to refresh.
     * @param JwtAlgorithmManager $manager   Algorithm manager instance.
     * @param JwtValidator|null   $validator Optional validator to check the bundle before refreshing.
     *
     * @return EncryptedJwtBundle New JWT bundle with refreshed timestamps.
     */
    public static function refreshTokenFromBundle(
        string $interval,
        EncryptedJwtBundle $bundle,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ): EncryptedJwtBundle
    {
        // Update issued-at to current time and expiration to the specified interval
        $bundle->getPayload()
                ->setIssuedAt('now')
                ->setExpiration($interval);
        
        $validator->assertValidBundle($bundle);
        
        $builder = new JwtTokenBuilder($manager);
        return $builder->createFromBundle($bundle);
    }
}
