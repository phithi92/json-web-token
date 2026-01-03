<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use DateTimeImmutable;
use JsonSerializable;
use Phithi92\JsonWebToken\Exceptions\Payload\ClaimAlreadyExistsException;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Exceptions\Token\EncryptedPayloadAlreadySetException;
use Phithi92\JsonWebToken\Exceptions\Token\EncryptedPayloadNotSetException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\Validator\ClaimValidator;

use function array_is_list;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_null;
use function is_string;
use function sprintf;

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

    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->claimValidator = new ClaimValidator();
        $this->claimHelper    = new DateClaimHelper($dateTime);
    }

    /**
     * Hydrate payload from an associative array (e.g. json_decode result).
     *
     * This method strictly validates RFC 7519 claim types.
     *
     * @throws InvalidFormatException
     */
    public function hydrateFromArray(mixed $claims): self
    {
        $this->assertValidPayloadStructure($claims);

        /** @var array<string, mixed> $claims */
        $this->hydrateClaims($claims);

        return $this;
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
     * Set a time-based claim.
     *
     * This method is intended for token creation and allows:
     * - date strings
     * - integers
     * - floats (NumericDate with fractional seconds)
     *
     * Hydrated JWT input MUST already contain NumericDate values.
     *
     * @throws InvalidDateTimeException
     */
    public function setClaimTimestamp(string $key, string|int|float $value): self
    {
        if (is_float($value) && $this->isTimeClaim($key)) {
            // NumericDate may be a float according to RFC 7519
            return $this->setRawClaim($key, $value, true);
        }

        $this->claimHelper->setClaimTimestamp(
            $this,
            $key,
            is_float($value) ? (int) $value : $value
        );

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
     *
     * @return self
     */
    public function addClaim(string $key, mixed $value): self
    {
        $this->claimValidator->ensureValidClaim($key, $value);

        if ($this->hasClaim($key)) {
            throw new ClaimAlreadyExistsException($key);
        }

        return $this->setRawClaim($key, $value, false);
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
     *
     * @return self
     */
    public function setClaim(string $key, mixed $value): self
    {
        $this->claimValidator->ensureValidClaim($key, $value);
        return $this->setRawClaim($key, $value, true);
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
        return (is_int($issued) || is_float($issued)) ? $issued : null;
    }

    public function setExpiration(string $interval): self
    {
        return $this->setClaimTimestamp('exp', $interval);
    }

    public function getExpiration(): int|float|null
    {
        $expires = $this->getClaim('exp');
        return (is_int($expires) || is_float($expires)) ? $expires : null;
    }

    public function setNotBefore(string $dateTime): self
    {
        return $this->setClaimTimestamp('nbf', $dateTime);
    }

    public function getNotBefore(): int|float|null
    {
        $nbf = $this->getClaim('nbf');
        return (is_int($nbf) || is_float($nbf)) ? $nbf : null;
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

    /**
     * Validate payload structure and registered claim types according to RFC 7519.
     *
     * Rules:
     * - Payload must be a JSON object (assoc array)
     * - Keys must be strings
     * - Values must be valid JSON values
     * - Registered claims must match RFC-defined types
     *
     * @throws InvalidFormatException
     */
    private function assertValidPayloadStructure(mixed $data): void
    {
        if (! is_array($data)) {
            throw new InvalidFormatException('Decoded JWT payload must be an object (assoc array).');
        }

        foreach ($data as $key => $value) {
            if (! is_string($key)) {
                throw new InvalidFormatException('All JWT claim keys must be strings.');
            }

            if (! $this->isValidJsonValue($value)) {
                throw new InvalidFormatException(
                    sprintf("JWT claim value for key '%s' must be a valid JSON value.", $key)
                );
            }

            // Registered Claim Names (RFC 7519)
            switch ($key) {
                case 'iss':
                case 'sub':
                case 'jti':
                    if (! is_string($value)) {
                        throw new InvalidFormatException(
                            sprintf("JWT registered claim '%s' must be a string.", $key)
                        );
                    }
                    break;

                case 'aud':
                    if (is_string($value)) {
                        break;
                    }
                    if (! (is_array($value) && array_is_list($value))) {
                        throw new InvalidFormatException(
                            "JWT registered claim 'aud' must be a string or an array of strings."
                        );
                    }
                    foreach ($value as $aud) {
                        if (! is_string($aud)) {
                            throw new InvalidFormatException(
                                "JWT registered claim 'aud' must be an array of strings."
                            );
                        }
                    }
                    break;

                case 'exp':
                case 'nbf':
                case 'iat':
                    // NumericDate = JSON number
                    if (! (is_int($value) || is_float($value))) {
                        throw new InvalidFormatException(
                            sprintf("JWT registered claim '%s' must be a NumericDate (number).", $key)
                        );
                    }
                    break;

                default:
                    // Private and public claims: no additional RFC restrictions
                    break;
            }
        }
    }

    /**
     * Apply validated claims to internal state.
     */
    private function hydrateClaims(array $claims): void
    {
        foreach ($claims as $key => $value) {
            if ($this->isTimeClaim($key)) {
                // Time claims are already NumericDate values when hydrated
                $this->setRawClaim($key, $value, true);
                continue;
            }

            $this->addClaim($key, $value);
        }
    }

    /**
     * Validate whether a value can be represented as JSON.
     */
    private function isValidJsonValue(mixed $v): bool
    {
        if (
            is_null($v)
            || is_bool($v)
            || is_int($v)
            || is_float($v)
            || is_string($v)
        ) {
            return true;
        }

        if (! is_array($v)) {
            return false;
        }

        foreach ($v as $k => $inner) {
            if (! (is_int($k) || is_string($k))) {
                return false;
            }
            if (! $this->isValidJsonValue($inner)) {
                return false;
            }
        }

        return true;
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
