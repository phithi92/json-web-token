<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidKeyTypeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;

use function gettype;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;

/**
 * Description of PayloadClaimValidator.
 *
 * @author phillipthiele
 */
final class ClaimValidator
{
    private const DECODE_JSON_DEPTH = 4;

    /**
     * Validates that a given JWT claim value is not empty or of invalid type.
     *
     * Rejects null values, empty strings, and empty arrays, as these are considered
     * semantically meaningless in the context of JWT claims. Also ensures that the
     * value is either a scalar or an array.
     *
     * @param int|string $key   the claim key being validated (used for error context)
     * @param mixed      $value the claim value to validate
     *
     * @throws EmptyFieldException       if the value is null, empty string, or empty array
     * @throws InvalidValueTypeException if the value is neither scalar nor array
     */
    public function ensureValidClaim(int|string $key, mixed $value): void
    {
        $resolvedKey = $this->assertJsonKey($key);

        if ($this->isEmpty($value)) {
            throw new EmptyFieldException((string) $resolvedKey);
        }

        if (! $this->isJsonValue($value)) {
            throw new InvalidValueTypeException((string) $resolvedKey, gettype($value));
        }
    }

    public function getJsonDepthLimit(): int
    {
        return self::DECODE_JSON_DEPTH;
    }

    /**
     * @param array<string,scalar|array<key-string,scalar>> $array
     *
     * @throws InvalidFormatException
     */
    public function assertValidPayloadDepth(array $array): void
    {
        if ($this->computeJsonDepth($array) > self::DECODE_JSON_DEPTH) {
            throw new InvalidFormatException(
                sprintf(
                    'Payload exceeds maximum allowed depth of %d',
                    self::DECODE_JSON_DEPTH
                )
            );
        }
    }

    /**
     * Recursively calculates the maximum depth of a nested array.
     */
    private function computeJsonDepth(mixed $value): int
    {
        if (! is_array($value)) {
            return 0; // scalars do not increase depth
        }

        $max = 0;
        foreach ($value as $v) {
            $d = $this->computeJsonDepth($v);
            if ($d > $max) {
                $max = $d;
            }
        }

        return $max + 1; // +1 for this array level
    }

    private function assertJsonKey(mixed $key): string|int
    {
        if (! is_string($key) && ! is_int($key)) {
            throw new InvalidKeyTypeException(gettype($key));
        }

        return $key;
    }

    private function isJsonValue(mixed $data): bool
    {
        if ($this->isJsonScalar($data)) {
            return true;
        }

        if (is_array($data)) {
            return $this->isJsonArray($data);
        }

        return false;
    }

    private function isJsonScalar(mixed $data): bool
    {
        return is_bool($data)
            || is_float($data)
            || is_int($data)
            || is_string($data)
            || $data === null;
    }

    /**
     * @param array<mixed> $data
     */
    private function isJsonArray(array $data): bool
    {
        foreach ($data as $v) {
            if (! $this->isJsonValue($v)) {
                return false;
            }
        }

        return true;
    }

    private function isEmpty(mixed $value): bool
    {
        return $value === null || $value === '' || $value === [];
    }
}
