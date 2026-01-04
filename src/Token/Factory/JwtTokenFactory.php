<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use WeakMap;

/**
 * Factory class for creating, encrypting, decrypting, and validating JWTs.
 *
 * This class orchestrates the full lifecycle of JSON Web Tokens, including:
 * - Creating JWTs with configurable algorithms and handlers.
 * - Applying and validating encryption, signatures, IVs, and CEKs.
 * - Decrypting and verifying existing tokens based on algorithm configuration.
 * - Delegating responsibilities to pluggable handler interfaces.
 *
 * Acts as a central access point to assemble or parse `JwtBundle` objects
 * using a configured `JwtKeyManager` and optional `JwtValidator`.
 */
final class JwtTokenFactory
{
    /**
     * Cache builders per manager without preventing GC of the manager instance.
     *
     * @var WeakMap<JwtKeyManager, JwtTokenBuilder>
     */
    private static WeakMap $builderCache;

    /**
     * Cache decryptors per manager without preventing GC of the manager instance.
     *
     * @var WeakMap<JwtKeyManager, JwtTokenDecryptor>
     */
    private static WeakMap $decryptorCache;

    /**
     * Creates a fully validated JWT bundle.
     *
     * This method performs:
     * - Payload validation
     * - Claim validation (via JwtValidator)
     * - Signing and/or encryption according to the algorithm
     */
    public static function createToken(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $builder = self::getBuilder(manager: $manager);

        return $builder->create(
            algorithm: $algorithm,
            payload: $payload,
            validator: $validator,
            kid: $kid
        );
    }

    /**
     * Convenience method for creating a token directly from an associative array.
     *
     * The array is converted into a JwtPayload before normal token creation.
     *
     * @param array<string, mixed> $claims
     */
    public static function createTokenFromArray(
        string $algorithm,
        JwtKeyManager $manager,
        array $claims,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $payload = (new JwtPayload())->hydrateFromArray(claims: $claims);

        return self::createToken(
            algorithm: $algorithm,
            manager: $manager,
            payload: $payload,
            validator: $validator,
            kid: $kid
        );
    }

    /**
     * ⚠️ SECURITY WARNING:
     * Creates a JWT without performing any claim validation.
     *
     * This method **bypasses all internal claim validation checks** and is intended
     * **exclusively** for controlled testing environments, stubbing, or internal tooling.
     * Signing, encryption, and header construction still run; only payload/claim
     * validation is skipped.
     */
    public static function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $builder = self::getBuilder(manager: $manager);

        return $builder->createWithoutValidation(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );
    }

    /**
     * Creates and serializes a JWT into its compact string representation.
     *
     * This is a shortcut for createToken() + JwtTokenParser::serialize().
     */
    public static function createTokenString(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): string {
        $bundle = self::createToken(
            algorithm: $algorithm,
            manager: $manager,
            payload: $payload,
            validator: $validator,
            kid: $kid
        );

        return JwtTokenParser::serialize(bundle: $bundle);
    }

    /**
     * Decrypts and validates a JWT string.
     *
     * This includes:
     * - Parsing
     * - Signature verification
     * - Decryption (if applicable)
     * - Claim validation
     */
    public static function decryptToken(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $processor = self::getDecryptor(manager: $manager);

        return $processor->decrypt(token: $token, validator: $validator);
    }

    /**
     * ⚠️ SECURITY WARNING
     *
     * Decrypts a token without validating claims.
     *
     * Use ONLY in trusted contexts.
     */
    public static function decryptTokenWithoutClaimValidation(
        string $token,
        JwtKeyManager $manager,
    ): JwtBundle {
        $processor = self::getDecryptor(manager: $manager);

        return $processor->decryptWithoutClaimValidation(token: $token);
    }

    /**
     * Validates only the claims of a JWT.
     *
     * The token is fully decrypted and verified first.
     * Returns false instead of throwing on validation failure.
     */
    public static function validateTokenClaims(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): bool {
        $validator ??= new JwtValidator();

        $bundle = self::decryptToken(
            token: $token,
            manager: $manager,
            validator: $validator
        );

        return $validator->isValid(payload: $bundle->getPayload());
    }

    /**
     * Reissues a JWT directly from a token string.
     *
     * The original token is parsed, filtered and re-signed with a new expiration.
     */
    public static function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return self::reissueBundle(
            interval: $interval,
            bundle: JwtTokenParser::parse($token),
            manager: $manager,
            validator: $validator
        );
    }

    /**
     * Reissues an existing bundle with refreshed temporal claims.
     *
     * Time-based claims are removed and regenerated.
     * Non-temporal claims are preserved.
     */
    public static function reissueBundle(
        string $interval,
        JwtBundle $bundle,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $payload = self::buildFilteredPayload(bundle: $bundle)
            ->setExpiration(interval: $interval);

        $newBundle = new JwtBundle(header: $bundle->getHeader(), payload: $payload);
        $validator ??= new JwtValidator();

        $validator->assertValidBundle(bundle: $newBundle);

        $builder = self::getBuilder(manager: $manager);

        return $builder->createFromBundle(bundle: $newBundle);
    }

    private static function buildFilteredPayload(JwtBundle $bundle): JwtPayload
    {
        $referencePayload = $bundle->getPayload();

        $payload = new JwtPayload();
        $filteredClaims = self::filterClaims(payload: $referencePayload);
        $payload->hydrateFromArray(claims: $filteredClaims);

        return $payload;
    }

    /** @return array<string, mixed> */
    private static function filterClaims(JwtPayload $payload): array
    {
        $claims = $payload->toArray();

        foreach (DateClaimHelper::TIME_CLAIMS as $key) {
            unset($claims[$key]);
        }

        return $claims;
    }

    private static function getBuilder(JwtKeyManager $manager): JwtTokenBuilder
    {
        self::$builderCache ??= new WeakMap();

        return self::$builderCache[$manager] ??= new JwtTokenBuilder(manager: $manager);
    }

    private static function getDecryptor(JwtKeyManager $manager): JwtTokenDecryptor
    {
        self::$decryptorCache ??= new WeakMap();

        return self::$decryptorCache[$manager] ??= new JwtTokenDecryptor(manager: $manager);
    }
}
