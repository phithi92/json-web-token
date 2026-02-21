<?php

declare(strict_types=1);

namespace Tests\phpunit\Crypto\Pipeline;

use Phithi92\JsonWebToken\Crypto\ContentEncryption\ContentEncryptionHandlerInterface;
use Phithi92\JsonWebToken\Crypto\ContentEncryption\DecryptionHandlerResult;
use Phithi92\JsonWebToken\Crypto\ContentEncryption\EncryptionHandlerResult;
use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmInvocation;
use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmMethodMap;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoAlgorithmInvoker;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoProcessingStage;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerResult;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\InvalidAlgorithmImplementationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\MissingAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtSignature;
use PHPUnit\Framework\TestCase;

final class CryptoAlgorithmInvokerTest extends TestCase
{
    public function testDispatchReturnsNullWhenHandlerNotConfigured(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(MissingAlgorithmConfigurationException::class);

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            []
        );
    }

    public function testDispatchThrowsWhenConfigMissingHandlerDefinition(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            [CryptoProcessingStage::Signature->interfaceClass() => 'invalid'],
        );
    }

    public function testDispatchThrowsWhenHandlerClassInvalid(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
            new JwtKeyManager(),
            new JwtBundle(new JwtHeader()),
            [CryptoProcessingStage::Signature->interfaceClass() => ['handler' => 123]],
        );
    }

    public function testDispatchThrowsWhenHandlerDoesNotImplementInterface(): void
    {
        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());

        $this->expectException(InvalidAlgorithmImplementationException::class);

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
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

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Signature,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
            new JwtKeyManager(),
            $bundle,
            [CryptoProcessingStage::Signature->interfaceClass() => [
                'handler' => TestSignatureHandler::class,
                'hash_algorithm' => 'sha256'
            ]],
        );

        $this->assertSame(['computeSignature'], TestSignatureHandler::$calls);
    }

    public function testDispatchThrowsWhenDirectEncryptionKeyLengthIsTooShort(): void
    {
        TestSignatureHandler::$calls = [];

        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());
        $manager = new JwtKeyManager();
        $manager->addPassphrase('short-key', 'dir-kid');

        $bundle = new JwtBundle(
            (new JwtHeader())
                ->setAlgorithm('dir')
                ->setKid('dir-kid')
        );
        $bundle->setEncryption(new JwtEncryptionData(
            iv: random_bytes(12),
            aad: 'header.payload'
        ));

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Payload,
            CryptoOperationDirection::Perform
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid direct encryption key length');

        $dispatcher->process(
            $invocation,
            $manager,
            $bundle,
            [CryptoProcessingStage::Payload->interfaceClass() => [
                'handler' => TestPayloadHandler::class,
                'length' => 128,
            ]],
        );
    }

    public function testDispatchAllowsDirectEncryptionKeyWithExactLength(): void
    {
        TestPayloadHandler::$calls = [];

        $dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());
        $manager = new JwtKeyManager();
        $manager->addPassphrase(random_bytes(16), 'dir-kid');

        $bundle = new JwtBundle(
            (new JwtHeader())
                ->setAlgorithm('dir')
                ->setKid('dir-kid')
        );
        $bundle->setEncryption(new JwtEncryptionData(
            iv: random_bytes(12),
            aad: 'header.payload'
        ));

        $invocation = new AlgorithmInvocation(
            CryptoProcessingStage::Payload,
            CryptoOperationDirection::Perform
        );

        $dispatcher->process(
            $invocation,
            $manager,
            $bundle,
            [CryptoProcessingStage::Payload->interfaceClass() => [
                'handler' => TestPayloadHandler::class,
                'length' => 128,
            ]],
        );

        $this->assertSame(['encryptPayload'], TestPayloadHandler::$calls);
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

        return new SignatureHandlerResult(new JwtSignature('computeSignature'));
    }
}

final class TestPayloadHandler implements ContentEncryptionHandlerInterface
{
    /** @var array<int, string> */
    public static array $calls = [];

    public function encryptPayload(
        string $data,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $additionalAuthenticatedData
    ): EncryptionHandlerResult {
        self::$calls[] = 'encryptPayload';

        return new EncryptionHandlerResult('ciphertext', 'tag');
    }

    public function decryptPayload(
        string $encryptedData,
        string $encryptionKey,
        int $cipherKeyLength,
        string $initializationVector,
        string $authTag,
        string $additionalAuthenticatedData
    ): DecryptionHandlerResult {
        self::$calls[] = 'decryptPayload';

        return new DecryptionHandlerResult('plaintext');
    }
}


final class NotAHandler
{
}
