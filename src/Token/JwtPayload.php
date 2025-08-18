<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use DateTimeImmutable;
use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidDateTimeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Exceptions\Token\EncryptedPayloadAlreadySetException;
use Phithi92\JsonWebToken\Exceptions\Token\EncryptedPayloadNotSetException;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\Validator\ClaimValidator;

/**
 * JwtPayload represents the payload part of a JSON Web Token.
 *
 * This class manages creation, validation and updates to claims data.
 * It supports standard claims such as iss, aud, iat, exp and nbf,
 * and allows custom claims to be added. Time based claims are
 * handled using DateTimeImmutable for consistency.
 */
class JwtPayload
{
    private readonly DateClaimHelper $claimHelper;
    private ?string $encryptedPayload = null;

    /** @var array<string, mixed> Claims data */
    private array $claims = [];

    private readonly ClaimValidator $claimValidator;

    /**
     * Constructor.
     *
     * @param DateTimeImmutable|null $dateTime Optional date to use for time based claims
     */
    public function __construct(?DateTimeImmutable $dateTime = null)
    {
        $this->claimValidator = new ClaimValidator();
        $this->claimHelper = new DateClaimHelper($dateTime);
    }

    public function getDateClaimHelper(): DateClaimHelper
    {
        return $this->claimHelper;
    }

    /**
     * Populate this payload from an associative array.
     *
     * Time based claims (exp, nbf, iat) are validated and stored
     * as timestamps or strings. Other claims are set directly.
     *
     * @param array<string, mixed> $data Claims input
     *
     * @throws InvalidValueTypeException If a time claim has an unsupported type
     */
    public function fromArray(array $data): self
    {
        foreach ($data as $key => $value) {
            // throws if claim or type is invalid
            $this->claimValidator->ensureValidClaim($key, $value);

            if (! $this->isTimeClaimKey($key)) {
                $this->setClaim($key, $value);
                continue; // process remaining claims
            }

            if (! $this->isTimeClaimValue($value)) {
                throw new InvalidDateTimeException($key);
            }

            // normalize time-based claims via helper (accepts string|int)
            $this->setClaimTimestamp($key, $value);
        }

        return $this;
    }

    /**
     * Return all claims as an associative array.
     *
     * Ensures iat is set by default if missing.
     *
     * @return array<string,mixed>
     *
     * @throws InvalidValueTypeException
     * @throws EmptyFieldException
     */
    public function toArray(): array
    {
        if ($this->getClaim('iat') === null) {
            $this->setClaimTimestamp('iat', 'now');
        }

        return $this->claims;
    }

    /**
     * Set a time based claim value as a timestamp.
     *
     * @param string $key Claim name
     * @param string|int $value Date string or timestamp
     */
    public function setClaimTimestamp(string $key, string|int $value): self
    {
        $this->claimHelper->setClaimTimestamp($this, $key, $value);
        return $this;
    }

    /**
     * Add a claim to the payload.
     *
     * @param string $key Claim name
     * @param mixed $value Claim value
     *
     * @throws InvalidValueTypeException
     * @throws EmptyFieldException
     */
    public function addClaim(string $key, mixed $value): self
    {
        return $this->setClaim($key, $value, false);
    }

    /**
     * Get a claim value by name.
     *
     * @param string $claim Claim name
     */
    public function getClaim(string $claim): mixed
    {
        return $this->claims[$claim] ?? null;
    }

    /**
     * Set the issuer claim.
     *
     * @param string $issuer Issuer value
     *
     * @throws InvalidValueTypeException
     * @throws EmptyFieldException
     */
    public function setIssuer(string $issuer): self
    {
        return $this->addClaim('iss', $issuer);
    }

    /**
     * Get the issuer claim.
     */
    public function getIssuer(): ?string
    {
        $issuer = $this->getClaim('iss');
        return is_string($issuer) ? $issuer : null;
    }

    /**
     * Set the audience claim.
     *
     * @param string|array<string> $audience Audience value
     *
     * @throws InvalidValueTypeException
     * @throws EmptyFieldException
     */
    public function setAudience(string|array $audience): self
    {
        return $this->addClaim('aud', $audience);
    }

    /**
     * Get the audience claim.
     *
     * @return string|array<mixed>|null
     */
    public function getAudience(): string|array|null
    {
        $audience = $this->getClaim('aud');
        return is_string($audience) || is_array($audience) ? $audience : null;
    }

    /**
     * Set the issued at claim.
     *
     * @param string $dateTime Date value
     */
    public function setIssuedAt(string $dateTime): self
    {
        return $this->setClaimTimestamp('iat', $dateTime);
    }

    /**
     * Get the issued at claim.
     */
    public function getIssuedAt(): int|null
    {
        $issued = $this->getClaim('iat');
        $resolvedIssued = is_int($issued) ? $issued : 0;
        return $resolvedIssued > 0 ? $resolvedIssued : null;
    }

    /**
     * Set the expiration claim.
     *
     * @param string $dateTime Date value
     *
     * @throws InvalidDateTimeException
     */
    public function setExpiration(string $dateTime): self
    {
        return $this->setClaimTimestamp('exp', $dateTime);
    }

    /**
     * Get the expiration claim.
     */
    public function getExpiration(): int|null
    {
        $expires = $this->getClaim('exp');
        $resolvedExpires = is_int($expires) ? $expires : 0;
        return $resolvedExpires > 0 ? $resolvedExpires : null;
    }

    /**
     * Set the not before claim.
     *
     * @param string $dateTime Date value
     *
     * @throws InvalidDateTimeException
     */
    public function setNotBefore(string $dateTime): self
    {
        return $this->setClaimTimestamp('nbf', $dateTime);
    }

    /**
     * Get the not before claim.
     */
    public function getNotBefore(): int|null
    {
        $nbf = $this->getClaim('nbf');
        $resolvedNbf = is_int($nbf) ? $nbf : 0;
        return $resolvedNbf > 0 ? $resolvedNbf : null;
    }

    /**
     * Check if a claim exists.
     *
     * @param string|int $field Claim name
     */
    public function hasClaim(string|int $field): bool
    {
        return array_key_exists($field, $this->claims);
    }

    /**
     * Set the encrypted payload string.
     *
     * @param string $sealedPayload Encrypted payload value
     * @param bool $overwrite Whether to overwrite existing value
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
     * Get the encrypted payload string.
     *
     * @throws EncryptedPayloadNotSetException
     */
    public function getEncryptedPayload(): string
    {
        return $this->encryptedPayload ?? throw new EncryptedPayloadNotSetException();
    }

    private function isTimeClaimKey(string $key): bool
    {
        return in_array($key, DateClaimHelper::TIME_CLAIMS, true);
    }

    /**
     * @phpstan-assert-if-true string|int $value
     */
    private function isTimeClaimValue(mixed $value): bool
    {
        return is_int($value) || is_string($value);
    }

    /**
     * Set a claim value.
     *
     * @param string $key Claim name
     * @param mixed $value Claim value
     * @param bool $overwrite Whether to overwrite existing value
     *
     * @throws EmptyFieldException
     * @throws InvalidValueTypeException
     */
    private function setClaim(string $key, mixed $value, bool $overwrite = false): self
    {
        $this->claimValidator->ensureValidClaim($key, $value);

        if ($this->hasClaim($key) === false || $overwrite) {
            $this->claims[$key] = $value;
        }

        return $this;
    }
}
