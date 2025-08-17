<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Factory;

final class ClassFactory
{
    /**
     * Creates a new instance of the given class.
     *
     * @template T of object
     *
     * @param class-string<T> $class  Fully qualified class name to instantiate.
     * @param list<mixed> $args       Constructor arguments.
     *
     * @return T                      Instance of the requested class.
     */
    public function create(string $class, array $args = []): object
    {
        return new $class(...$args);
    }
}
