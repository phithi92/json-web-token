<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Utilities;

use InvalidArgumentException;
use UnitEnum;

final class EnumUtils
{
    /**
     * Resolves an enum case by its name (not backing value).
     *
     * @template T of UnitEnum
     *
     * @param class-string<T> $enumClass The fully qualified enum class name
     * @param string          $name      The name of the enum case (e.g. 'INVALID_SIGNATURE')
     *
     * @return T
     *
     * @throws InvalidArgumentException If the class is not an enum or the case is invalid
     */
    public static function fromName(string $enumClass, string $name): UnitEnum
    {
        if (! enum_exists($enumClass)) {
            throw new InvalidArgumentException("Class '{$enumClass}' is not a valid enum.");
        }

        foreach ($enumClass::cases() as $case) {
            if ($case->name === $name) {
                return $case;
            }
        }

        throw new InvalidArgumentException("Invalid enum case name '{$name}' for enum {$enumClass}.");
    }
}
