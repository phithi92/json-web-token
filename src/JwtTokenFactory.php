<?php

namespace Phithi92\JsonWebToken;
declare(strict_types=1);

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Core\HandlerResolver;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionManagerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyManagementManagerInterface;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionKeyManagerInterface;
use Phithi92\JsonWebToken\Interfaces\InitializationVectorManagerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureManagerInterface;
use LogicException;

/**
 * Factory class for creating, encrypting, decrypting, and validating JWTs.
 *
 * This class orchestrates the full lifecycle of JSON Web Tokens, including:
 * - Creating JWTs with configurable algorithms and handlers.
 * - Applying and validating encryption, signatures, IVs, and CEKs.
 * - Decrypting and verifying existing tokens based on algorithm configuration.
 * - Delegating responsibilities to pluggable handler interfaces.
 *
 * Acts as a central access point to assemble or parse `EncryptedJwtBundle` objects
 * using a configured `JwtAlgorithmManager` and optional `JwtValidator`.
 */
final class JwtTokenFactory
{
    /**
     * Manages algorithm selection and configuration.
     *
     * @var JwtAlgorithmManager
     */
    private readonly JwtAlgorithmManager $manager;

    /**
     *
     *
     * @var JwtValidator
     */
    private readonly JwtValidator $validator;

    /**
     * Constructs the factory and resolves the appropriate processor.
     *
     * @param JwtAlgorithmManager $manager The algorithm manager instance.
     */
    public function __construct(
        JwtAlgorithmManager $manager,
        JwtValidator $validator = null
    ) {
        $this->manager = $manager;
        $this->validator = $validator ?? new JwtValidator();
    }

    /**
     * Creates a new encrypted JWT bundle from a given payload.
     *
     * This method validates the payload, prepares headers,
     * delegates CEK/key/IV/signature operations to configured handlers,
     * encrypts the payload, and returns a complete JWT structure.
     *
     * @param JwtPayload $payload The payload to embed in the token.
     * @return EncryptedJwtBundle The fully constructed and encrypted JWT.
     * @throws LogicException If any configured handler is missing or invalid.
     */
    public function create(JwtPayload $payload): EncryptedJwtBundle
    {
        // Validate the payload claims before proceeding
        $this->validator->assertValid($payload);

        return $this->createWithoutValidation($payload);
    }

    public function createWithoutValidation(JwtPayload $payload): EncryptedJwtBundle
    {
        // Load the current algorithm configuration
        $algorithmConfig = $this->manager->getConfiguration();

        // Determine the primary algorithm (signing or key management)
        $algorithmName = $algorithmConfig['alg'] ?? null;

        $tokenType = $algorithmConfig['token_type'] ?? null;
        if (! is_string($tokenType)) {
            throw new LogicException('Invalid configuration: missing or invalid "token_type" value');
        }

        if (! is_string($algorithmName)) {
            throw new LogicException('Invalid configuration: missing or invalid "alg" value');
        }

        // Initialize JWT header with type and algorithm identifiers
        $jwtHeader = new JwtHeader();
        $jwtHeader->setType($algorithmConfig['token_type']);
        $jwtHeader->setAlgorithm($algorithmName);

        if (is_string($algorithmConfig['enc'] ?? null)) {
            $jwtHeader->setEnc($algorithmConfig['enc']);
        }

        // Create initial token bundle with header and payload
        $jwtBundle = new EncryptedJwtBundle($jwtHeader, $payload);

        // --- CEK HANDLING ---
        // Delegate CEK generation or assignment to the configured handler
        if (isset($algorithmConfig['cek']) && is_array($algorithmConfig['cek'])) {
            /** @var ContentEncryptionKeyManagerInterface $cekHandler */
            $cekHandler = $this->resolveHandler(
                $algorithmConfig,
                'cek',
                ContentEncryptionKeyManagerInterface::class
            );
            $cekHandler->prepareCek($jwtBundle, $algorithmConfig['cek']);
        }

        // --- KEY MANAGEMENT ---
        // Delegate CEK wrapping (e.g., encryption) to key management handler
        if (isset($algorithmConfig['key_management']) && is_array($algorithmConfig['key_management'])) {
            /** @var KeyManagementManagerInterface $keyManager */
            $keyManager = $this->resolveHandler(
                $algorithmConfig,
                'key_management',
                KeyManagementManagerInterface::class
            );
            $keyManager->wrapKey($jwtBundle, $algorithmConfig['key_management']);
        }

        // --- SIGNATURE ---
        // Delegate signature generation to the configured signature handler
        if (isset($algorithmConfig['signing_algorithm']) && is_array($algorithmConfig['signing_algorithm'])) {
            /** @var SignatureManagerInterface $signatureManager */
            $signatureManager = $this->resolveHandler(
                $algorithmConfig,
                'signing_algorithm',
                SignatureManagerInterface::class
            );
            $signatureManager->computeSignature($jwtBundle, $algorithmConfig['signing_algorithm']);
        }

        // --- IV HANDLING ---
        // Delegate IV generation to the configured initialization vector handler
        if (isset($algorithmConfig['iv']) && is_array($algorithmConfig['iv'])) {
            /** @var InitializationVectorManagerInterface $ivManager */
            $ivManager = $this->resolveHandler(
                $algorithmConfig,
                'iv',
                InitializationVectorManagerInterface::class
            );
            $ivManager->prepareIv($jwtBundle, $algorithmConfig['iv']);
        }

        // --- PAYLOAD ENCRYPTION ---
        // Delegate encryption of the payload to the content encryption handler
        if (isset($algorithmConfig['content_encryption']) && is_array($algorithmConfig['content_encryption'])) {
            /** @var ContentEncryptionManagerInterface $payloadDecryptor */
            $payloadDecryptor = $this->resolveHandler(
                $algorithmConfig,
                'content_encryption',
                ContentEncryptionManagerInterface::class
            );
            $payloadDecryptor->encryptPayload($jwtBundle, $algorithmConfig['content_encryption']);
        }

        return $jwtBundle;
    }

    /**
     * Decrypts and verifies a given encrypted JWT bundle.
     *
     * This method delegates CEK unwrapping, IV validation, signature verification,
     * and payload decryption to the configured handlers according to the
     * algorithm setup derived from the token header.
     *
     * @param EncryptedJwtBundle $jwtBundle The encrypted JWT bundle.
     * @return EncryptedJwtBundle The fully decrypted and verified token bundle.
     * @throws LogicException If any configured handler is missing or invalid.
     */
    public function decrypt(EncryptedJwtBundle $jwtBundle): EncryptedJwtBundle
    {
        $jwtBundle = $this->decryptWithoutValidation($jwtBundle);

        // Final validation of the fully assembled token
        $this->validator->assertValidBundle($jwtBundle);

        return $jwtBundle;
    }

    public function decryptWithoutValidation(EncryptedJwtBundle $jwtBundle): EncryptedJwtBundle
    {
        // Resolve algorithm name from token header
        $algorithmName = $jwtBundle->getHeader()->getAlgorithm();

        if ($algorithmName === null) {
            throw new Exception('no algorithm');
        }

        if ($algorithmName === 'dir' && $jwtBundle->getHeader()->getEnc() !== null) {
            $algorithmName = $jwtBundle->getHeader()->getEnc();
        }

        // Apply algorithm context to internal manager
        $this->manager->setAlgorithm($algorithmName);
        $algorithmConfig = $this->manager->getConfiguration();

        // --- KEY MANAGEMENT ---
        // Delegate CEK unwrapping (e.g., decrypting or deriving CEK) to key management handler
        if (isset($algorithmConfig['key_management']) && is_array($algorithmConfig['key_management'])) {
            /** @var KeyManagementManagerInterface $keyManager */
            $keyManager = $this->resolveHandler(
                $algorithmConfig,
                'key_management',
                KeyManagementManagerInterface::class
            );
            $keyManager->unwrapKey($jwtBundle, $algorithmConfig['key_management']);
        }

        // --- CEK VALIDATION ---
        // Delegate CEK validation or derivation (if needed) to the configured CEK handler
        if (isset($algorithmConfig['cek']) && is_array($algorithmConfig['cek'])) {
            /** @var ContentEncryptionKeyManagerInterface $cekHandler */
            $cekHandler = $this->resolveHandler(
                $algorithmConfig,
                'cek',
                ContentEncryptionKeyManagerInterface::class
            );
            $cekHandler->validateCek($jwtBundle, $algorithmConfig['cek']);
        }

        // --- IV VALIDATION ---
        // Delegate IV verification to the configured initialization vector handler
        if (isset($algorithmConfig['iv']) && is_array($algorithmConfig['iv'])) {
            /** @var InitializationVectorManagerInterface $ivManager */
            $ivManager = $this->resolveHandler(
                $algorithmConfig,
                'iv',
                InitializationVectorManagerInterface::class
            );
            $ivManager->validateIv($jwtBundle, $algorithmConfig['iv']);
        }

        // --- SIGNATURE VERIFICATION ---
        // Delegate verification of token signature to the configured signature handler
        if (isset($algorithmConfig['signing_algorithm']) && is_array($algorithmConfig['signing_algorithm'])) {
            /** @var SignatureManagerInterface $signatureManager */
            $signatureManager = $this->resolveHandler(
                $algorithmConfig,
                'signing_algorithm',
                SignatureManagerInterface::class
            );
            $signatureManager->validateSignature($jwtBundle, $algorithmConfig['signing_algorithm']);
        }

        // --- PAYLOAD DECRYPTION ---
        // Delegate decryption of the encrypted payload to the configured content encryption handler
        if (isset($algorithmConfig['content_encryption']) && is_array($algorithmConfig['content_encryption'])) {
            /** @var ContentEncryptionManagerInterface $payloadDecryptor */
            $payloadDecryptor = $this->resolveHandler(
                $algorithmConfig,
                'content_encryption',
                ContentEncryptionManagerInterface::class
            );
            $payloadDecryptor->decryptPayload($jwtBundle, $algorithmConfig['content_encryption']);
        }

        return $jwtBundle;
    }


    /**
     * Static helper to create a token in one step.
     *
     * @param JwtAlgorithmManager $algorithm The algorithm manager.
     * @param JwtPayload $payload The token payload.
     * @return EncryptedJwtBundle The created encrypted token.
     */
    public static function createToken(JwtAlgorithmManager $algorithm, JwtPayload $payload, JwtValidator $validator = null): EncryptedJwtBundle
    {
        return (new self($algorithm, $validator))->create($payload);
    }

    /**
     * Static helper to decrypt a JWT token with the given algorithm.
     *
     * @param JwtAlgorithmManager $algorithm The algorithm manager.
     * @param EncryptedJwtBundle $jwtBundle The encrypted token to decrypt.
     * @return EncryptedJwtBundle The decrypted and verified token.
     */
    public static function decryptToken(
        JwtAlgorithmManager $algorithm,
        EncryptedJwtBundle $jwtBundle,
        JwtValidator $validator = null
    ): EncryptedJwtBundle {
        return (new self($algorithm, $validator))->decrypt($jwtBundle);
    }

    /**
     * @template T of object
     * @param class-string<T> $interface
     * @param array<string, array<string, string>|string> $config
     * @return T
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
