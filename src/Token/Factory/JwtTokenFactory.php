<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

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
    private const RETAINED_CLAIMS = ['sub', 'aud', 'iss'];

    private static ?JwtTokenBuilder $builderCache = null;

    private static ?JwtTokenDecryptor $decryptorCache = null;

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
        $builder = self::getBuilder($manager);
        return $builder->create($algorithm, $payload, $validator, $kid);
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
        $builder = self::getBuilder($manager);
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
        $processor = self::getDecryptor($manager);
        return $processor->decrypt($token, $validator);
    }

    /**
     * Decrypts a JWT string without performing validation.
     *
     * @param string              $token       Serialized JWT string.
     * @param JwtAlgorithmManager $manager   Algorithm manager.
     *
     * @return EncryptedJwtBundle Decrypted JWT bundle.
     */
    public static function decryptTokenWithoutClaimValidation(
        string $token,
        JwtAlgorithmManager $manager
    ): EncryptedJwtBundle {
        $processor = self::getDecryptor($manager);
        return $processor->decryptWithoutClaimValidation($token);
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
    public static function validateTokenClaim(
        string $token,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ): bool {
        $processor = self::getDecryptor($manager);
        $bundle = $processor->decrypt($token, $validator);

        $validator ??= new JwtValidator();
        return $validator->isValid($bundle->getPayload());
    }

    public static function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ): EncryptedJwtBundle {
        $bundle = JwtTokenParser::parse($token);
        return self::reissueBundle($interval, $bundle, $manager, $validator);
    }

    /**
     * Refreshes a JWT by cloning its payload and updating the timestamps.
     *
     * @param string              $interval        Expiration interval (e.g., "+1 hour").
     * @param EncryptedJwtBundle  $bundle          Existing JWT bundle to refresh.
     * @param JwtAlgorithmManager $manager         Algorithm manager instance.
     * @param JwtValidator|null   $validator       Optional validator to check the bundle before refreshing.
     * @param array<int, string>  $retainedClaims  Expiration interval (e.g., "+1 hour").
     *
     * @return EncryptedJwtBundle New JWT bundle with refreshed timestamps.
     */
    public static function reissueBundle(
        string $interval,
        EncryptedJwtBundle $bundle,
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null,
        array $retainedClaims = []
    ): EncryptedJwtBundle {
        $payload = self::buildFilteredPayload($bundle, $retainedClaims);

        $newBundle = new EncryptedJwtBundle($bundle->getHeader(), $payload);

        $validator ??= new JwtValidator();
        $validator->assertValidBundle($newBundle);

        $builder = self::getBuilder($manager);
        return $builder->createFromBundle($newBundle);
    }

    /**
     * @param array<int, string> $retained
     */
    private static function buildFilteredPayload(EncryptedJwtBundle $bundle, array $retained): JwtPayload
    {
        $payloadArray = $bundle->getPayload()->toArray();

        $oldPayload = $bundle->getPayload();
        $newPayload = new JwtPayload($oldPayload->getReferenceTime());

        $retainedClaims = array_merge(self::RETAINED_CLAIMS, $retained);

        foreach ($retained as $claim) {
            if ($oldPayload->hasClaim($claim)) {
                // @phpstan-ignore-next-line
                $newPayload->addClaim($claim, $oldPayload->getClaim($claim));
            }
        }

        return $newPayload;
    }

    private static function getBuilder(JwtAlgorithmManager $manager): JwtTokenBuilder
    {
        return self::$builderCache ??= new JwtTokenBuilder($manager);
    }

    private static function getDecryptor(JwtAlgorithmManager $manager): JwtTokenDecryptor
    {
        return self::$decryptorCache ??= new JwtTokenDecryptor($manager);
    }
}
