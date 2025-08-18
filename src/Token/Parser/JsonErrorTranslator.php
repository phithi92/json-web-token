<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Factory\ClassFactory;
use Throwable;

final class JsonErrorTranslator
{
    private ClassFactory $factory;

    /** @var class-string<Throwable> */
    private readonly string $defaultFallback;

    /**
     * @param class-string<Throwable>|null     $defaultFallback
     */
    public function __construct(
        ClassFactory $factory,
        ?string $defaultFallback = null
    ) {
        $this->factory = $factory;
        $this->defaultFallback = $defaultFallback ?? InvalidArgumentException::class;
    }

    /**
     * @param class-string<Throwable>|null     $fallback
     */
    public function translate(Throwable $e, ?int $depth = null, ?string $fallback = null): Throwable
    {
        $codeEnum = JsonErrorCode::tryFrom((int) $e->getCode());
        if ($codeEnum instanceof JsonErrorCode) {
            return $codeEnum->toException($depth);
        }

        /** @param class-string $fb */
        $fb = $fallback ?? $this->defaultFallback;
        return $this->factory->create($fb, [$e->getMessage(), $e]);
    }

    /**
     * @param class-string<Throwable>|null $fallback
     */
    public function rethrow(Throwable $e, ?int $depth = null, ?string $fallback = null): never
    {
        throw $this->translate($e, $depth, $fallback);
    }
}
