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
        throw match ($e->getCode()) {
            JSON_ERROR_SYNTAX,
            JSON_ERROR_CTRL_CHAR,
            JSON_ERROR_STATE_MISMATCH => new MalformedTokenException(),

            JSON_ERROR_UTF8 => new MalformedUtf8Exception(),

            JSON_ERROR_DEPTH => new InvalidDepthException($depth ?? 0),

            default => $this->createThrowableFromFactory($fallback, [$e->getMessage()])
        };
    }

    /**
     * @param class-string $fallback
     * @param list<string> $args
     *
     * @throws \LogicException
     */
    private function createThrowableFromFactory(string $fallback, array $args): Throwable
    {
        $exception = $this->classFactory->create($fallback, $args);

        if (! $exception instanceof Throwable) {
            throw new \LogicException(sprintf(
                'ClassFactory did not return a Throwable for "%s". Got: %s',
                $fallback,
                $exception::class
            ));
        }

        return $exception;
    }
}
