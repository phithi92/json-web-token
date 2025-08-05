<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions;

/**
 * Trait ErrorMessageTrait
 *
 * This trait provides a `getMessage` method to generate a formatted error message.
 * The method uses `sprintf` to replace placeholders in the error message string (`$this->value`)
 * with the provided details (`$details`). This allows for flexible and dynamic generation
 * of error messages with variable content.
 *
 * @method string getMessage(mixed ...$details) Accepts any number of detail values as parameters
 * and returns a formatted error message as a string.
 */
trait ErrorMessageTrait
{
    public function getMessage(string|int|float|bool|null ...$details): string
    {
        if (count($details) > 0) {
            return sprintf($this->value, ...$details);
        }

        return $this->value;
    }
}
