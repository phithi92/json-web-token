<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use LogicException;
use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

use function array_diff_key;
use function array_flip;
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
        $builder = self::getBuilder($manager);

        return $builder->create($algorithm, $payload, $validator, $kid);
    }

    /**
     * Creates a JWT from an associative array of claims.
     *
     * @param string               $algorithm algorithm name
     * @param JwtKeyManager  $manager   algorithm manager instance
     * @param array<string,string> $claims    associative array of JWT claims
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
        $payload = new JwtPayload();
        $payload->fromArray($claims);

        return self::createToken($algorithm, $manager, $payload, $validator, $kid);
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
     *
     * @throws LogicException if used in production context
     */
    public static function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $builder = self::getBuilder($manager);

        return $builder->createWithoutValidation($algorithm, $payload, $kid);
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
        $bundle = self::createToken($algorithm, $manager, $payload, $validator, $kid);

        return JwtTokenParser::serialize($bundle);
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
        $processor = self::getDecryptor($manager);

        return $processor->decrypt($token, $validator);
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
        $processor = self::getDecryptor($manager);

        return $processor->decryptWithoutClaimValidation($token);
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
    public static function validateTokenClaim(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): bool {
        $processor = self::getDecryptor($manager);
        $bundle = $processor->decrypt($token, $validator);

        $validator ??= new JwtValidator();

        return $validator->isValid($bundle->getPayload());
    }

    public static function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $bundle = JwtTokenParser::parse($token);

        return self::reissueBundle($interval, $bundle, $manager, $validator);
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
        $payload = self::buildFilteredPayload($bundle)
            ->setExpiration($interval);

        $newBundle = new JwtBundle($bundle->getHeader(), $payload);

        $validator ??= new JwtValidator();
        $validator->assertValidBundle($newBundle);

        $builder = self::getBuilder($manager);

        return $builder->createFromBundle($newBundle);
    }

    private static function buildFilteredPayload(JwtBundle $bundle): JwtPayload
    {
        $oldPayload = $bundle->getPayload();
        $newPayload = new JwtPayload($oldPayload->getDateClaimHelper()->getReferenceTime());

        $timeClaims = $newPayload->getDateClaimHelper()::TIME_CLAIMS;

        $claims = $oldPayload->toArray();

        $cleanedClaims = array_diff_key($claims, array_flip($timeClaims));

        return $newPayload->fromArray($cleanedClaims);
    }

    private static function getBuilder(JwtKeyManager $manager): JwtTokenBuilder
    {
        $cacheId = self::getObjectId($manager);

        return self::$builderCache[$cacheId] ??= new JwtTokenBuilder($manager);
    }

    private static function getDecryptor(JwtKeyManager $manager): JwtTokenDecryptor
    {
        $cacheId = self::getObjectId($manager);

        return self::$decryptorCache[$cacheId] ??= new JwtTokenDecryptor($manager);
    }

    private static function getObjectId(object $object): int
    {
        return spl_object_id($object);
    }
}
