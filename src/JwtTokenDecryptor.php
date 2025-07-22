<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

final class JwtTokenDecryptor
{
    /**
     * Handler-Mapping-Konfiguration: [config-key => [Interface, Methode]]
     */
    private const HANDLER_MAPPINGS = [
        'key_management' => [
            KeyHandlerInterface::class,
            'unwrapKey',
        ],
        'cek' => [
            CekHandlerInterface::class,
            'validateCek',
        ],
        'iv' => [
            IvHandlerInterface::class,
            'validateIv',
        ],
        'signing_algorithm' => [
            SignatureHandlerInterface::class,
            'validateSignature',
        ],
        'content_encryption' => [
            PayloadHandlerInterface::class,
            'decryptPayload',
        ],
    ];
    /**
     * @var JwtAlgorithmManager Handles algorithm resolution and handler configuration.
     */
    private readonly JwtAlgorithmManager $manager;

    /**
     * @var JwtValidator Validates the integrity and structure of the decrypted JWT bundle.
     */
    private readonly JwtValidator $validator;

    /**
     * JwtTokenDecryptor constructor.
     *
     * @param JwtAlgorithmManager $manager   Provides cryptographic handler configurations.
     * @param JwtValidator|null   $validator Optional validator; defaults to JwtValidator if not provided.
     */
    public function __construct(
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ) {
        $this->manager = $manager;
        $this->validator = ($validator ?? new JwtValidator());
    }

    /**
     * Fully decrypts and validates a JWT token.
     *
     * @param string $token The encrypted JWT string.
     *
     * @return EncryptedJwtBundle The fully decrypted and validated JWT payload bundle.
     */
    public function decrypt(string $token): EncryptedJwtBundle
    {
        $bundle = $this->decryptWithoutValidation($token);
        $this->validator->assertValidBundle($bundle);
        return $bundle;
    }

    /**
     * Decrypts a JWT token without running any validation checks.
     *
     * Useful for debugging or low-trust environments where validation is handled elsewhere.
     *
     * @param string $token The encrypted JWT string.
     *
     * @return EncryptedJwtBundle The decrypted JWT payload bundle.
     */
    public function decryptWithoutValidation(string $token): EncryptedJwtBundle
    {
        $bundle = JwtTokenParser::parse($token);

        $algorithm = $this->resolveAlgorithm($bundle);

        $config = $this->manager->getConfiguration($algorithm);

        foreach (self::HANDLER_MAPPINGS as $key => [$interface, $method]) {
            /*
             * @var class-string<object> $interface
             */
            $this->applyHandler($bundle, $config, $key, $interface, $method);
        }

        return $bundle;
    }

    /**
     * Resolves the algorithm used for key decryption or encryption based on JWT headers.
     *
     * If 'alg' is 'dir' (direct symmetric key), falls back to 'enc' for further processing.
     *
     * @return string The resolved algorithm identifier.
     *
     * @throws InvalidTokenException If no algorithm is specified in the JWT header.
     */
    private function resolveAlgorithm(EncryptedJwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $alg = $header->getAlgorithm() ?? throw new InvalidTokenException('no algorithm');

        return $alg === 'dir' && $header->getEnc() !== null ? $header->getEnc() : $alg;
    }

    /**
     * Applies a specific handler to the JWT bundle based on the configuration key.
     *
     * If the configuration entry is missing or invalid, the handler is skipped.
     *
     * @template T of object
     *
     * @param EncryptedJwtBundle   $bundle    The JWT bundle being processed.
     * @param array<string, mixed> $config    Configuration map for the current algorithm.
     * @param string               $key       Configuration key corresponding to the handler.
     * @param class-string<T>      $interface Expected interface of the handler.
     * @param string               $method    The handler method to invoke.
     */
    private function applyHandler(
        EncryptedJwtBundle $bundle,
        array $config,
        string $key,
        string $interface,
        string $method
    ): void {
        if (! isset($config[$key]) || ! is_array($config[$key])) {
            return;
        }

        $handler = $this->resolveHandler($config, $key, $interface);
        $handler->{$method}($bundle, $config[$key]);
    }

    /**
     * Resolves a configured handler instance for a specific cryptographic role.
     *
     * @template T of object
     *
     * @param array<string, mixed> $config    Full configuration for the algorithm.
     * @param string               $key       Configuration key under which the handler is defined.
     * @param class-string<T>      $interface Required interface the handler must implement.
     *
     * @return T A resolved and validated handler instance.
     */
    private function resolveHandler(array $config, string $key, string $interface): object
    {
        return HandlerResolver::resolve(
            $config,
            $key,
            $interface,
            $this->manager
        );
    }
}
