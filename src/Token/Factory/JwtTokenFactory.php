<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\Helper\UtcClock;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

use function spl_object_id;

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
    /** @var array<int, JwtTokenBuilder> */
    private static array $builderCache = [];

    /** @var array<int, JwtTokenDecryptor> */
    private static array $decryptorCache = [];

    private static ?UtcClock $utcClock = null;

    /**
     * Creates a signed and/or encrypted JWT using the provided payload and algorithm.
     *
     * @param string              $algorithm Algorithm name (e.g., 'RS256').
     * @param JwtKeyManager $manager   algorithm manager instance
     * @param JwtPayload|null     $payload   optional Payload object containing JWT claims
     * @param JwtValidator|null   $validator optional validator instance
     * @param string|null         $kid       optional key ID
     *
     * @return JwtBundle resulting token bundle
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
     * Creates a JWT from an associative array of claims.
     *
     * @param string               $algorithm algorithm name
     * @param JwtKeyManager  $manager   algorithm manager instance
     * @param array<string,mixed> $claims    associative array of JWT claims
     * @param JwtValidator|null    $validator optional validator instance
     * @param string|null          $kid       optional key ID
     *
     * @return JwtBundle resulting token bundle
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
     *
     * @param string              $algorithm algorithm name
     * @param JwtKeyManager $manager   algorithm manager instance
     * @param JwtPayload|null     $payload   optional JWT payload
     * @param string|null         $kid       optional key ID
     *
     * @return JwtBundle resulting token bundle
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
     * Creates a JWT and returns it as a serialized string (JWT compact format).
     *
     * @param string              $algorithm algorithm name
     * @param JwtKeyManager $manager   algorithm manager instance
     * @param JwtPayload|null     $payload   optional JWT payload
     * @param JwtValidator|null   $validator optional validator
     * @param string|null         $kid       optional key ID
     *
     * @return string JWT as a compact string
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
     * Decrypts and validates a JWT string using the provided manager and validator.
     *
     * @param string              $token     serialized JWT string
     * @param JwtKeyManager $manager   algorithm manager
     * @param JwtValidator|null   $validator optional validator
     *
     * @return JwtBundle decrypted and parsed JWT bundle
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
     * Decrypts a JWT string without performing validation.
     *
     * @param string              $token   serialized JWT string
     * @param JwtKeyManager $manager algorithm manager
     *
     * @return JwtBundle decrypted JWT bundle
     */
    public static function decryptTokenWithoutClaimValidation(
        string $token,
        JwtKeyManager $manager,
    ): JwtBundle {
        $processor = self::getDecryptor(manager: $manager);

        return $processor->decryptWithoutClaimValidation(token: $token);
    }

    /**
     * Validates a JWT string by decrypting and passing it to a JwtValidator.
     *
     * @param string              $token     serialized JWT string
     * @param JwtKeyManager $manager   algorithm manager instance
     * @param JwtValidator        $validator validator instance
     *
     * @return bool true if the token is valid, false otherwise
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
     * Refreshes a JWT by cloning its payload and updating the timestamps.
     *
     * @param string              $interval  Expiration interval (e.g., "+1 hour").
     * @param JwtBundle  $bundle    existing JWT bundle to refresh
     * @param JwtKeyManager $manager   algorithm manager instance
     * @param JwtValidator|null   $validator optional validator to check the bundle before refreshing
     *
     * @return JwtBundle new JWT bundle with refreshed timestamps
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

    private static function getUtcClock(): UtcClock
    {
        return self::$utcClock ??= new UtcClock();
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
        $cacheId = self::getObjectId(object: $manager);

        return self::$builderCache[$cacheId] ??= new JwtTokenBuilder(manager: $manager);
    }

    private static function getDecryptor(JwtKeyManager $manager): JwtTokenDecryptor
    {
        $cacheId = self::getObjectId(object: $manager);

        return self::$decryptorCache[$cacheId] ??= new JwtTokenDecryptor(manager: $manager);
    }

    private static function getObjectId(object $object): int
    {
        return spl_object_id($object);
    }
}
