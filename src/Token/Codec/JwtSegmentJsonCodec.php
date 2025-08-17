<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Json\InvalidDepthException;
use Phithi92\JsonWebToken\Exceptions\Json\MalformedTokenException;
use Phithi92\JsonWebToken\Exceptions\Json\MalformedUtf8Exception;
use Phithi92\JsonWebToken\Factory\ClassFactory;
use Phithi92\JsonWebToken\Token\Parser\JsonErrorTranslator;
use Throwable;

abstract class JwtSegmentJsonCodec
{
    protected JsonErrorTranslator $jsonErrorTranslator;
    protected ClassFactory $classFactory;

    public function __construct()
    {
        $this->classFactory = new ClassFactory();
        $this->jsonErrorTranslator = new JsonErrorTranslator($this->classFactory);
    }

    /**
     * @param class-string $fallback
     *
     * @throws MalformedTokenException
     * @throws MalformedUtf8Exception
     * @throws InvalidDepthException
     */
    protected function rethrowJsonException(Throwable $e, string $fallback, ?int $depth = null): never
    {
        match ($e->getCode()) {
            JSON_ERROR_SYNTAX,
            JSON_ERROR_CTRL_CHAR,
            JSON_ERROR_STATE_MISMATCH => throw new MalformedTokenException(),

            JSON_ERROR_UTF8 => throw new MalformedUtf8Exception(),

            JSON_ERROR_DEPTH => throw new InvalidDepthException($depth ?? 0),

            default => null,
        };

        throw $this->classFactory->create($fallback, [$e->getMessage()]);
    }
}
