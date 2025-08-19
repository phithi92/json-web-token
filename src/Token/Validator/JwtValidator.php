<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use InvalidArgumentException;
use LogicException;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidAudienceException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuedAtException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuerException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotBeforeOlderThanIatException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotYetValidException;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ValueNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidPrivateClaimException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingPrivateClaimException;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Handler\HandlerInvoker;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;

/**
 * JwtValidator provides validation logic for standard JWT claims.
 *
 * Supports audience, issuer, expiration, not-before, and issued-at validation,
 * including optional clock skew adjustment.
 *
 * Intended for post-decryption and post-signature verification.
 */
class JwtValidator
{
    private const IS_METHODS = [
        'isValidPrivateClaims',
        'isNotExpired',
        'isNotBeforeValid',
        'isIssuedAtValid',
        'isValidIssuer',
        'isValidAudience',
    ];

    private const ASSERT_METHODS = [
        'assertValidPrivateClaims',
        'assertNotExpired',
        'assertNotBeforeValid',
        'assertIssuedAtValid',
        'assertValidIssuer',
        'assertValidAudience',
    ];

    // The expected issuer value (public claim iss).
    private ?string $expectedIssuer = null;

    // The expected audience value (public claim aud).
    private ?string $expectedAudience = null;
    //
    // Allowed clock skew in seconds.
    private int $clockSkew = 0;

    /**
     * @var array<string, scalar|null>
     */
    private array $expectedClaims;

    /**
     * Frozen timestamp for one validation run.
     * Set in isValid()/assertValid(), cleared afterwards.
     */
    private ?int $currentTime = null;

    private HandlerInvoker $invoker;

    /**
     * JwtValidator constructor.
     *
     * @param string|null $expectedIssuer   Optional expected "iss" (issuer) claim value.
     *                                      If set, tokens must match this exact issuer.
     * @param string|null $expectedAudience Optional expected "aud" (audience) claim value.
     *                                      Supports string or array in token payload.
     * @param int         $clockSkew        Allowed clock skew (in seconds) when validating
     *                                      time-based claims like "exp", "nbf", and "iat".
     *                                      Helps tolerate minor time drift.
     * @param array<string, scalar|null> $expectedClaims Optional associative array of expected private claims.
     *                                                   - If value is null, only claim existence is required.
     *                                                   - If value is set, exact match is required.
     */
    public function __construct(
        ?string $expectedIssuer = null,
        ?string $expectedAudience = null,
        int $clockSkew = 0,
        array $expectedClaims = []
    ) {
        if ($clockSkew < 0) {
            throw new InvalidArgumentException('clockSkew must be >= 0');
        }
        $this->clockSkew = $clockSkew;
        $this->expectedIssuer = $expectedIssuer;
        $this->expectedAudience = $expectedAudience;
        $this->expectedClaims = $expectedClaims;
        $this->invoker = new HandlerInvoker();
    }

    /**
     * Validates all supported standard claims.
     *
     * @return bool True if all checks pass.
     */
    public function isValid(JwtPayload $payload): bool
    {
        $this->currentTime = time();
        try {
            foreach (self::IS_METHODS as $method) {
                if ($this->invoker->invoke($this, $method, [$payload]) === false) {
                    return false;
                }
            }
            return true;
        } finally {
            $this->currentTime = null;
        }
    }

    /**
     * Validates the "exp" (expiration) claim.
     *
     * @return bool True if token has not expired.
     */
    public function isNotExpired(JwtPayload $payload): bool
    {
        $exp = $payload->getExpiration();
        return $exp === null || ($exp + $this->clockSkew) > $this->now();
    }

    /**
     * Validates the "nbf" (not before) claim.
     *
     * @return bool True if token is valid at current time.
     */
    public function isNotBeforeValid(JwtPayload $payload): bool
    {
        $nbf = $payload->getNotBefore();
        return $nbf === null || ($nbf - $this->clockSkew) <= $this->now();
    }

    /**
     * Validates the "iat" (issued at) claim.
     *
     * @return bool True if token was issued in the past.
     */
    public function isIssuedAtValid(JwtPayload $payload): bool
    {
        $iat = $payload->getIssuedAt();
        return $iat === null || ($iat - $this->clockSkew) <= $this->now();
    }

    /**
     * Validates the "iss" (issuer) claim against the expected value.
     *
     * @return bool True if issuer is valid or not enforced.
     */
    public function isValidIssuer(JwtPayload $payload): bool
    {
        return $this->expectedIssuer === null || $payload->getIssuer() === $this->expectedIssuer;
    }

    /**
     * Validates the "aud" (audience) claim against the expected value.
     *
     * @return bool True if audience matches or is not enforced.
     */
    public function isValidAudience(JwtPayload $payload): bool
    {
        if ($this->expectedAudience === null) {
            return true;
        }

        $aud = $payload->getAudience();

        return is_array($aud) ? in_array($this->expectedAudience, $aud, true) : $aud === $this->expectedAudience;
    }

    /**
     * Validates the given encrypted JWT bundle.
     *
     * @throws PayloadException On any validation failure
     * @throws TokenException On any validation failure
     */
    public function assertValidBundle(EncryptedJwtBundle $bundle): void
    {
        $this->assertValid($bundle->getPayload());
    }

    /**
     * Runs all validation checks on the given JWT payload.
     *
     * @throws PayloadException On any validation failure
     * @throws TokenException On any validation failure
     */
    public function assertValid(JwtPayload $payload): void
    {
        $this->currentTime = time();
        try {
            foreach (self::ASSERT_METHODS as $method) {
                $this->invoker->invoke($this, $method, [$payload]);
            }
        } finally {
            $this->currentTime = null;
        }
    }

    /**
     * Validates optional private claims in the JWT payload.
     *
     * - If an expected value is null, only the existence of the claim is required.
     * - If an expected value is set, the actual value must match exactly.
     *
     * @return bool True if all expected private claims are valid.
     */
    public function isValidPrivateClaims(JwtPayload $payload): bool
    {
        foreach ($this->expectedClaims as $key => $expectedValue) {
            // Retrieve the actual claim value from the payload
            $actualValue = $payload->getClaim($key);

            // If the claim is missing and we expect existence than invalid
            if ($actualValue === null) {
                return false;
            }

            // If only checking for existence, and the claim exists than valid
            if ($expectedValue === null) {
                continue;
            }

            // If the actual value doesn't match the expected one than invalid
            if ($actualValue !== $expectedValue) {
                return false;
            }
        }

        // All private claims are present and valid
        return true;
    }

    /**
     * Asserts that all expected private claims exist and match their expected values.
     *
     * - If expected value is null, only existence is required.
     * - If expected value is set, actual value must match exactly.
     *
     * @throws InvalidPrivateClaimException
     * @throws MissingPrivateClaimException
     */
    public function assertValidPrivateClaims(JwtPayload $payload): void
    {
        foreach ($this->expectedClaims as $key => $expectedValue) {
            if (! is_string($expectedValue) && ! is_int($expectedValue) && ! is_null($expectedValue)) {
                throw new LogicException('Misconfigured private claim value type');
            }

            $this->validateClaim($key, $payload, $expectedValue);
        }
    }

    /**
     * Validates the 'exp' (expiration) claim.
     *
     * @throws ExpiredPayloadException If the token has expired
     * @throws ValueNotFoundException If the 'exp' claim is missing
     */
    public function assertNotExpired(JwtPayload $payload): void
    {
        if (! $this->isNotExpired($payload)) {
            throw new ExpiredPayloadException();
        }
    }

    /**
     * Validates the 'nbf' (not before) claim relative to 'iat' and current time.
     *
     * @throws NotBeforeOlderThanIatException If 'nbf' is before 'iat' minus clock skew
     * @throws NotYetValidException If the token is not yet valid
     */
    public function assertNotBeforeValid(JwtPayload $payload): void
    {
        $nbf = $payload->getNotBefore();
        $iat = $payload->getIssuedAt();

        if ($nbf === null) {
            return;
        }

        if ($iat !== null && $nbf < $iat) {
            throw new NotBeforeOlderThanIatException();
        }

        if ($nbf - $this->clockSkew > $this->now()) {
            throw new NotYetValidException();
        }
    }

    /**
     * Validates the 'iat' (issued at) claim.
     *
     * @throws InvalidIssuedAtException If 'iat' is in the future (with clock skew)
     */
    public function assertIssuedAtValid(JwtPayload $payload): void
    {
        if (! $this->isIssuedAtValid($payload)) {
            throw new InvalidIssuedAtException();
        }
    }

    /**
     * Validates the 'iss' (issuer) claim against the expected issuer.
     *
     * @throws InvalidIssuerException If issuer doesn't match expected
     */
    public function assertValidIssuer(JwtPayload $payload): void
    {
        if ($this->expectedIssuer !== null && $payload->getIssuer() !== $this->expectedIssuer) {
            $resolvedIssuer = $payload->getIssuer() ?? 'Not set in Payload';
            throw new InvalidIssuerException($this->expectedIssuer, $resolvedIssuer);
        }
    }

    /**
     * Validates the 'aud' (audience) claim against the expected audience.
     *
     * @throws InvalidAudienceException If the audience doesn't match expected
     */
    public function assertValidAudience(JwtPayload $payload): void
    {
        if ($this->expectedAudience === null) {
            return;
        }

        $aud = $payload->getAudience();

        $valid = is_array($aud) ? in_array($this->expectedAudience, $aud, true) : $aud === $this->expectedAudience;

        if (! $valid) {
            throw new InvalidAudienceException();
        }
    }

    private function now(): int
    {
        return $this->currentTime ?? time();
    }

    private function validateClaim(string $key, JwtPayload $payload, string|int|null $expectedValue): void
    {
        if (! $payload->hasClaim($key)) {
            throw new MissingPrivateClaimException($key);
        }

        $actualValue = $payload->getClaim($key);

        if ($expectedValue !== null && $actualValue !== $expectedValue) {
            throw new InvalidPrivateClaimException($key, is_string($expectedValue) ? $expectedValue : '');
        }
    }
}
