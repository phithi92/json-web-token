<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingJwtIdException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtTokenService
{
    public function __construct(
        private readonly JwtTokenCreator $creator,
        private readonly JwtTokenReader $reader,
        private readonly JwtClaimsValidationService $claimsValidator,
        private readonly JwtTokenReissuer $reissuer,
    ) {
    }

    /**
     * Delegates JWT creation to the configured token creator instance.
     *
     * This is a convenience wrapper around the creator service that maintains
     * the same interface while allowing for dependency injection flexibility.
     *
     * @param non-empty-string $algorithm JWT signing algorithm
     * @param JwtKeyManager $manager Key management instance
     * @param JwtPayload|null $payload Optional claims payload
     * @param JwtValidator|null $validator Optional validator (uses creator's default if null)
     * @param string|null $kid Optional key identifier
     *
     * @return JwtBundle Validated JWT bundle
     */
    public function createToken(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->creator->createToken($algorithm, $manager, $payload, $validator, $kid);
    }

    /**
     * Delegates array-based JWT creation to the configured token creator instance.
     *
     * Convenience wrapper that converts array claims to a payload object before
     * delegating to the creator service, maintaining consistent interface behavior.
     *
     * @param non-empty-string $algorithm JWT signing algorithm
     * @param JwtKeyManager $manager Key management instance
     * @param array<non-empty-string, mixed> $claims JWT claims as key-value pairs
     * @param JwtValidator|null $validator Optional validator (uses creator's default if null)
     * @param string|null $kid Optional key identifier
     *
     * @return JwtBundle Validated JWT bundle
     */
    public function createTokenFromArray(
        string $algorithm,
        JwtKeyManager $manager,
        array $claims,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->creator->createTokenFromArray($algorithm, $manager, $claims, $validator, $kid);
    }

    /**
     * ⚠️ DANGER: This method bypasses ALL claim validations including:
     * - Expiration checks (exp)
     * - Issuer validation (iss)
     * - Audience validation (aud)
     * - Token identifier checks (jti)
     *
     * ❌ NEVER USE IN PRODUCTION unless you have implemented alternative security measures
     * and fully understand the security implications.
     *
     * Creates a JWT without performing claim validation.
     *
     * @param non-empty-string $algorithm JWT signing algorithm
     * @param JwtKeyManager $manager Key management instance
     * @param JwtPayload|null $payload Optional claims payload
     * @param string|null $kid Optional key identifier
     *
     * @return JwtBundle Unvalidated JWT bundle
     */
    public function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->creator->createTokenWithoutClaimValidation($algorithm, $manager, $payload, $kid);
    }

    /**
     * Creates and serializes a JWT into its compact string representation.
     *
     * This convenience method combines token creation and serialization into a single call,
     * returning the JWT in its standard JWS Compact Serialization format (RFC 7515 Section 3.1).
     *
     * @param non-empty-string $algorithm JWT signing algorithm (e.g., 'HS256', 'RS256')
     * @param JwtKeyManager $manager Key management instance providing signing keys
     * @param JwtPayload|null $payload Optional claims payload to include in the token
     * @param JwtValidator|null $validator Optional validator instance (uses default if null)
     * @param string|null $kid Optional key identifier for key rotation scenarios
     *
     * @return non-empty-string JWT in JWS Compact Serialization format
     */
    public function createTokenString(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): string {
        $bundle = $this->createToken($algorithm, $manager, $payload, $validator, $kid);

        return JwtBundleCodec::serialize($bundle);
    }

    /**
     * Decrypts and validates an encrypted JWT (JWE) into a JWT bundle.
     *
     * This method handles the complete decryption process including:
     * - Key resolution via JwtKeyManager
     * - Content decryption
     * - Optional validation of claims (when validator is provided)
     * - Structural validation of the JWT format
     *
     * @param non-empty-string $token Encrypted JWT in JWE Compact Serialization format (RFC 7516)
     * @param JwtKeyManager $manager Key management instance providing decryption keys
     * @param JwtValidator|null $validator Optional validator instance (uses default if null)
     *
     * @return JwtBundle Decrypted and validated JWT bundle
     */
    public function decryptToken(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reader->decryptToken($token, $manager, $validator);
    }

    /**
     * Decrypts a JWT without performing ANY claim validation.
     *
     * ⚠️ SECURITY WARNING: This method bypasses ALL security validations including:
     *    - Expiration checks (exp)
     *    - Issuer validation (iss)
     *    - Audience validation (aud)
     *    - Token identifier checks (jti)
     *    - Signature verification (for nested JWTs)
     *    - Critical header parameters (crit)
     *
     * ❌ NEVER USE IN PRODUCTION unless:
     *    1. You have implemented alternative security measures
     *    2. You fully understand the security implications
     *    3. The token comes from a fully trusted source
     *    4. You perform manual validation after decryption
     *
     * @param non-empty-string $token Encrypted JWT in JWE Compact Serialization format (RFC 7516)
     * @param JwtKeyManager $manager Key management instance providing decryption keys
     *
     * @return JwtBundle Decrypted but UNVALIDATED JWT bundle
     */
    public function decryptTokenWithoutClaimValidation(
        string $token,
        JwtKeyManager $manager,
    ): JwtBundle {
        return $this->reader->decryptTokenWithoutClaimValidation($token, $manager);
    }

    /**
     * Validates JWT claims according to configured validation rules.
     *
     * Performs comprehensive validation of all standard and custom claims including:
     * - Standard claims (iss, sub, aud, exp, nbf, iat, jti)
     * - Custom claims defined in the validator
     * - Claim value types and formats
     * - Time-based claims (exp, nbf, iat)
     * - Critical header parameters (if present)
     *
     * @param JwtBundle $bundle The JWT bundle containing payload to validate
     * @param JwtValidator $validator Validator instance with configured rules
     *
     * @return bool True if all claims pass validation, false otherwise
     */
    public function validateTokenClaims(
        JwtBundle $bundle,
        JwtValidator $validator,
    ): bool {
        return $validator->isValid($bundle->getPayload());
    }

    public function validateTokenClaimsFromToken(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): bool {
        return $this->claimsValidator->validateTokenClaims($token, $manager, $validator);
    }

    /**
     * Reissues a JWT bundle from an existing token with updated expiration.
     *
     * This method provides a complete token lifecycle management:
     * 1. Decrypts/verifies the input token
     * 2. Validates all claims (unless validator is null)
     * 3. Updates expiration time according to specified interval
     * 4. Issues a new token with fresh signature/encryption
     * 5. Returns a new validated JWT bundle
     *
     * @param non-empty-string $token JWT in compact serialization format (JWS or JWE)
     * @param string $interval Interval specification string
     *                                     (e.g., 'PT1H' for 1 hour, 'P1D' for 1 day)
     * @param JwtKeyManager $manager Key management instance for decryption and reissuing
     * @param JwtValidator|null $validator Optional validator instance (skips validation if null)
     *
     * @return JwtBundle New JWT bundle with updated expiration
     */
    public function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reissuer->reissueBundleFromToken($token, $interval, $manager, $validator);
    }

    public function reissueBundle(
        string $interval,
        JwtBundle $bundle,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reissuer->reissueBundle($interval, $bundle, $manager, $validator);
    }

    public function denyJwtId(string $jwtId, int $ttl, JwtValidator $validator): void
    {
        $jwtIdValidator = $validator->getJwtIdValidator();
        if ($jwtIdValidator === null) {
            throw new LogicException(
                'Cannot deny JWT ID: no JWT ID validator is configured. ' .
                'Please ensure JwtValidator is properly initialized with a JwtIdValidator.'
            );
        }

        if ($ttl <= 0) {
            return;
        }

        $jwtIdValidator->deny(new JwtIdInput($jwtId), $ttl);
    }

    public function denyBundle(JwtBundle $bundle, JwtValidator $validator): void
    {
        $jwtId = $bundle->getPayload()->getJwtId();
        if ($jwtId === null) {
            throw new MissingJwtIdException();
        }

        $exp = $bundle->getPayload()->getExpiration();
        if ($exp === null) {
            throw new JtiManagementException();
        }


        $this->denyJwtId($jwtId, $ttl, $validator);
    }
}
