<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use InvalidArgumentException;
use Throwable;

final class JsonErrorTranslator
{
    /** @var class-string<Throwable> */
    private readonly string $defaultFallback;

    /**
     * @param class-string<Throwable>|null     $defaultFallback
     */
    public function __construct(
        ?string $defaultFallback = null
    ) {
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
        $class = $fallback ?? $this->defaultFallback;

        return new $class(...[$e->getMessage(), $e]);
    }

    /**
     * @param class-string<Throwable>|null $fallback
     */
    public function rethrow(Throwable $e, ?int $depth = null, ?string $fallback = null): never
    {
        throw $this->translate($e, $depth, $fallback);
    }
}
