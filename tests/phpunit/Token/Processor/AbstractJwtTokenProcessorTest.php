<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Processor;

use Phithi92\JsonWebToken\Config\Provider\AlgorithmConfigurationProvider;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekHandlerInterface;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekHandlerResult;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerResult;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use PHPUnit\Framework\TestCase;

final class AbstractJwtTokenProcessorTest extends TestCase
{
    public function testDispatchHandlersRespectsPriority(): void
    {
        RecordingHandler::$calls = [];

        $provider = new class () implements AlgorithmConfigurationProvider {
            public function get(string $algorithm): array
            {
                return [
                    CekHandlerInterface::class => ['handler' => RecordingCekHandler::class],
                    SignatureHandlerInterface::class => [
                        'handler' => RecordingSignatureHandler::class,
                        'hash_algorithm' => 'sha256',
                    ],
                ];
            }

            public function isSupported(string $algorithm): bool
            {
                return true;
            }
        };

        $manager = new JwtKeyManager($provider);
        $processor = new class (CryptoOperationDirection::Perform, $manager) extends AbstractJwtTokenProcessor {
            public function run(string $algorithm, JwtBundle $bundle): void
            {
                $this->dispatchHandlers($algorithm, $bundle);
            }
        };

        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'));

        $processor->run('HS256', $bundle);

        $this->assertSame(['cek', 'signature'], RecordingHandler::$calls);
    }
}

class RecordingHandler
{
    /** @var array<int, string> */
    public static array $calls = [];
}

final class RecordingCekHandler extends RecordingHandler implements CekHandlerInterface
{
    public function initializeCek(string $algorithm, int $length): CekHandlerResult
    {
        self::$calls[] = 'cek';

        return new CekHandlerResult(contentEncryptionKey: 'cek');
    }
}

final class RecordingSignatureHandler extends RecordingHandler implements SignatureHandlerInterface
{
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        self::$calls[] = 'signature-validate';
    }

    public function computeSignature(string $kid, string $algorithm, string $singinInput): SignatureHandlerResult
    {
        self::$calls[] = 'signature';

        return new SignatureHandlerResult(signature: new JwtSignature('signature'));
    }
}
