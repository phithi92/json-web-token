<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use Phithi92\JsonWebToken\Exceptions\Payload\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidKeyTypeException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidValueTypeException;

use function gettype;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;

final class ClaimValidator
{
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
