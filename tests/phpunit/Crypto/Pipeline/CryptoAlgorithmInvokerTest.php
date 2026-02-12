<?php

declare(strict_types=1);

namespace Tests\phpunit\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmInvocation;
use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmMethodMap;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoAlgorithmInvoker;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoProcessingStage;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerResult;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\InvalidAlgorithmImplementationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\MissingAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtSignature;
use PHPUnit\Framework\TestCase;

final class CryptoAlgorithmInvokerTest extends TestCase
{
    public function testDispatchReturnsNullWhenHandlerNotConfigured(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(MissingAlgorithmConfigurationException::class);

        $invokation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invokation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            []
        );
    }

    public function testDispatchThrowsWhenConfigMissingHandlerDefinition(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(MissingAlgorithmConfigurationException::class);

        $invokation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invokation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            [CryptoProcessingStage::Signature->interfaceClass() => 'invalid'],
        );
    }

    public function testDispatchThrowsWhenHandlerClassInvalid(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $invokation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invokation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => 123]],
        );
    }

    public function testDispatchThrowsWhenHandlerDoesNotImplementInterface(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $invokation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invokation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => NotAHandler::class]],
        );
    }

    public function testDispatchInvokesConfiguredHandler(): void
    {
        TestSignatureHandler::$calls = [];

        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());
        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'));

        $invokation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invokation,
            new JwtKeyManager(),
            $bundle,
            [CryptoProcessingStage::Signature->interfaceClass() => [
                'handler' => TestSignatureHandler::class,
                'hash_algorithm' => 'sha256'
            ]],
        );

        $this->assertSame(['computeSignature'], TestSignatureHandler::$calls);
    }
}

final class TestSignatureHandler implements SignatureHandlerInterface
{
    /** @var array<int, string> */
    public static array $calls = [];

    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        self::$calls[] = 'validateSignature';
    }

    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult
    {
        self::$calls[] = 'computeSignature';

        return new SignatureHandlerResult(signature: new JwtSignature('computeSignature'));
    }
}

final class NotAHandler
{
}
