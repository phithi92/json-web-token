<?php

declare(strict_types=1);

namespace Tests\phpunit\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmMethodMap;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoAlgorithmInvoker;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoProcessingStage;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\InvalidAlgorithmImplementationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\MissingAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use PHPUnit\Framework\TestCase;

final class CryptoAlgorithmInvokerTest extends TestCase
{
    public function testDispatchReturnsNullWhenHandlerNotConfigured(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $result = $dispatcher->dispatch(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform,
            new JwtKeyManager(),
            [],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );

        $this->assertNull($result);
    }

    public function testDispatchThrowsWhenConfigMissingHandlerDefinition(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(MissingAlgorithmConfigurationException::class);

        $dispatcher->dispatch(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform,
            new JwtKeyManager(),
            [CryptoProcessingStage::Signature->interfaceClass() => 'invalid'],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchThrowsWhenHandlerClassInvalid(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $dispatcher->dispatch(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform,
            new JwtKeyManager(),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => 123]],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchThrowsWhenHandlerDoesNotImplementInterface(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $dispatcher->dispatch(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform,
            new JwtKeyManager(),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => NotAHandler::class]],
            ['bundle' => new JwtBundle(new JwtHeader())]
        );
    }

    public function testDispatchInvokesConfiguredHandler(): void
    {
        TestSignatureHandler::$calls = [];

        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());
        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'));

        $dispatcher->dispatch(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform,
            new JwtKeyManager(),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => TestSignatureHandler::class]],
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
