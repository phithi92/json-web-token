<?php

declare(strict_types=1);

namespace Tests\phpunit\Handler;

use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerClassDefinitionException;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerImplementationException;
use Phithi92\JsonWebToken\Exceptions\Handler\MissingHandlerConfigurationException;
use Phithi92\JsonWebToken\Handler\HandlerDispatcher;
use Phithi92\JsonWebToken\Handler\HandlerMethodResolver;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\HandlerTarget;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use PHPUnit\Framework\TestCase;

final class HandlerDispatcherTest extends TestCase
{
    public function testDispatchReturnsNullWhenHandlerNotConfigured(): void
    {
        $dispatcher = new HandlerDispatcher(new HandlerMethodResolver());

        $result = $dispatcher->dispatch(
            HandlerTarget::Signature,
            HandlerOperation::Perform,
            new JwtKeyManager(),
            [],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );

        $this->assertNull($result);
    }

    public function testDispatchThrowsWhenConfigMissingHandlerDefinition(): void
    {
        $dispatcher = new HandlerDispatcher(new HandlerMethodResolver());

        $this->expectException(MissingHandlerConfigurationException::class);

        $dispatcher->dispatch(
            HandlerTarget::Signature,
            HandlerOperation::Perform,
            new JwtKeyManager(),
            [HandlerTarget::Signature->interfaceClass() => 'invalid'],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchThrowsWhenHandlerClassInvalid(): void
    {
        $dispatcher = new HandlerDispatcher(new HandlerMethodResolver());

        $this->expectException(InvalidHandlerClassDefinitionException::class);

        $dispatcher->dispatch(
            HandlerTarget::Signature,
            HandlerOperation::Perform,
            new JwtKeyManager(),
            [HandlerTarget::Signature->interfaceClass() => ['handler' => 123]],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchThrowsWhenHandlerDoesNotImplementInterface(): void
    {
        $dispatcher = new HandlerDispatcher(new HandlerMethodResolver());

        $this->expectException(InvalidHandlerImplementationException::class);

        $dispatcher->dispatch(
            HandlerTarget::Signature,
            HandlerOperation::Perform,
            new JwtKeyManager(),
            [HandlerTarget::Signature->interfaceClass() => ['handler' => NotAHandler::class]],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchInvokesConfiguredHandler(): void
    {
        TestSignatureHandler::$calls = [];

        $dispatcher = new HandlerDispatcher(new HandlerMethodResolver());
        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'));

        $dispatcher->dispatch(
            HandlerTarget::Signature,
            HandlerOperation::Perform,
            new JwtKeyManager(),
            [HandlerTarget::Signature->interfaceClass() => ['handler' => TestSignatureHandler::class]],
            ['bundle' => $bundle]
        );

        $this->assertSame(['computeSignature'], TestSignatureHandler::$calls);
    }
}

final class TestSignatureHandler implements SignatureHandlerInterface
{
    /** @var array<int, string> */
    public static array $calls = [];

    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        self::$calls[] = 'validateSignature';
    }

    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        self::$calls[] = 'computeSignature';
    }
}

final class NotAHandler
{
}
