<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use JsonSerializable;
use Phithi92\JsonWebToken\Exceptions\Payload\ClaimAlreadyExistsException;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\EncryptedPayloadAlreadySetException;
use Phithi92\JsonWebToken\Exceptions\Payload\EncryptedPayloadNotSetException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\Validator\ClaimValidator;

use function array_is_list;
use function is_array;
use function is_float;
use function is_int;
use function is_string;

/**
 * Represents the payload part of a JSON Web Token (JWT).
 *
 * This implementation follows RFC 7519 (JWT) semantics:
 * - Registered claim names use the types defined by the RFC
 * - NumericDate claims (iat, nbf, exp) are represented as numbers
 * - No implicit default claims are added during serialization
 *
 * The class supports two use cases:
 * 1. Building JWTs programmatically (date strings allowed via helpers)
 * 2. Hydrating JWT payloads decoded from JSON (RFC-typed values only)
 */
final class JwtPayload implements JsonSerializable
{
    private readonly DateClaimHelper $claimHelper;
    private readonly ClaimValidator $claimValidator;

    /**
     * Encrypted payload (used for JWE-like scenarios).
     */
    private ?string $encryptedPayload = null;

    /**
     * Stored JWT claims.
     *
     * @var array<string, mixed>
     */
    private array $claims = [];

    public function __construct()
    {
        $this->claimValidator = new ClaimValidator();
        $this->claimHelper = new DateClaimHelper();
    }

    /**
     * Return the JWT payload claims as an associative array.
     *
     * This method returns the currently stored claims exactly as they are.
     * It does NOT apply any implicit defaults and does NOT mutate internal state.
     *
     * Typical use cases:
     * - Inspecting claims
     * - Validating decoded JWT payloads
     * - Serializing fully-defined payloads
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }

    /**
     * Return the JWT payload claims as an associative array with default claims applied.
     *
     * This method is intended for JWT creation (builder-style usage).
     * It MAY mutate the internal payload state by adding default claims
     * that are commonly required when issuing a token.
     *
     * Currently applied defaults:
     * - "iat" (issued at): set to the current time if missing
     *
     * @return array<string, mixed>
     */
    public function toArrayWithDefaults(): array
    {
        if (! $this->hasClaim('iat')) {
            $this->setIssuedAt('now');
        }

        return $this->toArray();
    }

    /**
     * Serialize payload for json_encode().
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Set a time-based JWT claim (NumericDate as defined by RFC 7519).
     *
     * This method is intended for token creation and supports the following
     * value types **exclusively for registered time-based claims**
     * (e.g. "iat", "nbf", "exp"):
     *
     * - string : Date/time expressions (e.g. "now", "+1 hour")
     * - int    : NumericDate (seconds since UNIX epoch)
     * - float  : NumericDate with fractional seconds
     *
     * Floats are permitted **only** for time-based claims and MUST NOT be used
     * for non-temporal or custom claims.
     *
     * When hydrating a JWT payload from decoded JSON, time-based claims MUST
     * already be provided as NumericDate values (int or float).
     *
     * @throws InvalidDateTimeException If the given value is not valid for a
     *                                  time-based claim or cannot be converted
     *                                  to a valid NumericDate.
     */
    public function setClaimTimestamp(string $key, string|int|float $value): self
    {
        // Accept numeric strings as NumericDate as well (common when coming from JSON / env)
        if (is_string($value) && is_numeric($value)) {
            $value = str_contains($value, '.')
                ? (float) $value
                : (int) $value;
        }

        if (is_int($value) || is_float($value)) {
            if (! $this->isTimeClaim($key)) {
                throw new InvalidDateTimeException($key);
            }

            return $this->setClaim($key, $value);
        }

        if (! $this->isTimeClaim($key)) {
            throw new InvalidDateTimeException($key);
        }

        $timestamp = $this->claimHelper->toTimestamp($value);
        $this->setClaim($key, $timestamp);

        return $this;
    }

    /**
     * Add a new claim to the JWT payload.
     *
     * This method adds the claim only if it does not already exist.
     * If a claim with the same name is already present, an exception is thrown.
     *
     * This is useful for:
     * - preventing accidental overwrites of security-sensitive claims
     * - enforcing explicit intent when modifying existing claims
     *
     * @param string $key   Claim name
     * @param mixed  $value Claim value
     *
     * @throws ClaimAlreadyExistsException If the claim already exists
     * @throws InvalidValueTypeException   If the claim value type is invalid
     * @throws EmptyFieldException         If the claim value is empty or invalid
     */
    public function addClaim(string $key, mixed $value): self
    {
        $this->claimValidator->ensureValidClaim($key, $value);

        if ($this->hasClaim($key)) {
            throw new ClaimAlreadyExistsException($key);
        }

        return $this->setRawClaim(
            key: $key,
            value: $value,
            overwrite: false
        );
    }

    /**
     * Set a claim value, overwriting any existing value.
     *
     * This method will always assign the given value to the claim name,
     * replacing any previously stored value.
     *
     * This is intended for explicit, intentional updates where overwriting
     * an existing claim is desired.
     *
     * @param string $key   Claim name
     * @param mixed  $value Claim value
     *
     * @throws InvalidValueTypeException If the claim value type is invalid
     * @throws EmptyFieldException       If the claim value is empty or invalid
     */
    public function setClaim(string $key, mixed $value): self
    {
        $this->claimValidator->ensureValidClaim($key, $value);
        return $this->setRawClaim(
            key: $key,
            value: $value,
            overwrite: true
        );
    }

    /**
     * Get a claim by name.
     */
    public function getClaim(string $claim): mixed
    {
        return $this->claims[$claim] ?? null;
    }

    /**
     * Set the issuer (iss) claim.
     */
    public function setIssuer(string $issuer): self
    {
        return $this->addClaim('iss', $issuer);
    }

    public function getIssuer(): ?string
    {
        $issuer = $this->getClaim('iss');
        return is_string($issuer) ? $issuer : null;
    }

    /**
     * Set the JWT ID (jti) claim.
     */
    public function setJwtId(string $jwtId): self
    {
        return $this->addClaim('jti', $jwtId);
    }

    public function getJwtId(): ?string
    {
        $jwtId = $this->getClaim('jti');
        return is_string($jwtId) ? $jwtId : null;
    }

    /**
     * Set the audience (aud) claim.
     *
     * @param string|array<string> $audience
     */
    public function setAudience(string|array $audience): self
    {
        return $this->addClaim('aud', $audience);
    }

    /**
     * Get the audience (aud) claim.
     *
     * @return string|array<string>|null
     */
    public function getAudience(): string|array|null
    {
        /** @var mixed $audience */
        $audience = $this->getClaim('aud');

        if (is_string($audience)) {
            return $audience;
        }

        if (is_array($audience) && array_is_list($audience)) {
            foreach ($audience as $a) {
                if (! is_string($a)) {
                    return null;
                }
            }

            /** @var list<string> $audience */
            return $audience;
        }

        return null;
    }

    /**
     * Set the issued-at (iat) claim using a date string.
     */
    public function setIssuedAt(string $dateTime): self
    {
        return $this->setClaimTimestamp('iat', $dateTime);
    }

    /**
     * Get the issued-at (iat) claim.
     *
     * NumericDate according to RFC 7519.
     */
    public function getIssuedAt(): int|float|null
    {
        $issued = $this->getClaim('iat');
        return is_int($issued) || is_float($issued) ? $issued : null;
    }

    public function setExpiration(string $interval): self
    {
        return $this->setClaimTimestamp('exp', $interval);
    }

    public function getExpiration(): int|float|null
    {
        $expires = $this->getClaim('exp');
        return is_int($expires) || is_float($expires) ? $expires : null;
    }

    public function setNotBefore(string $dateTime): self
    {
        return $this->setClaimTimestamp('nbf', $dateTime);
    }

    public function getNotBefore(): int|float|null
    {
        $nbf = $this->getClaim('nbf');
        return is_int($nbf) || is_float($nbf) ? $nbf : null;
    }

    /**
     * Check whether a claim exists.
     */
    public function hasClaim(string $field): bool
    {
        return isset($this->claims[$field]);
    }

    /**
     * Set encrypted payload value.
     *
     * Used for encrypted JWT representations.
     *
     * @throws EncryptedPayloadAlreadySetException
     */
    public function setEncryptedPayload(string $sealedPayload, bool $overwrite = false): self
    {
        if ($this->encryptedPayload !== null) {
            if ($this->encryptedPayload === $sealedPayload) {
                return $this;
            }

            if (! $overwrite) {
                throw new EncryptedPayloadAlreadySetException();
            }
        }

        $this->encryptedPayload = $sealedPayload;
        return $this;
    }

    /**
     * Get encrypted payload value.
     *
     * @throws EncryptedPayloadNotSetException
     */
    public function getEncryptedPayload(): string
    {
        return $this->encryptedPayload ?? throw new EncryptedPayloadNotSetException();
    }

    private function isTimeClaim(string $key): bool
    {
        return isset(DateClaimHelper::TIME_CLAIMS[$key]);
    }

    /**
     * Set claim value without additional validation.
     */
    private function setRawClaim(string $key, mixed $value, bool $overwrite = false): self
    {
        if (! $this->hasClaim($key) || $overwrite) {
            $this->claims[$key] = $value;
        }
        return $this;
    }
}
