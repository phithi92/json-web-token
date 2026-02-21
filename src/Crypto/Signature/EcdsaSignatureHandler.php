<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtSignature;
use SensitiveParameter;
use ValueError;

use function implode;
use function is_array;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_sign;
use function openssl_verify;
use function sprintf;

class EcdsaSignatureHandler extends AbstractSignatureHandler
{
    private OpenSslErrorHelper $errorHelper;

    /**
     * Cache validated keys by "kid|role|alg".
     *
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private array $validatedKeys = [];

    public function __construct(JwtKeyManager $manager, ?KidResolverInterface $kidResolver = null)
    {
        parent::__construct($manager, $kidResolver);
        $this->errorHelper = new OpenSslErrorHelper();
    }

    /**
     * Computes an ECDSA digital signature for the given signing input.
     *
     * @param non-empty-string $kid Key identifier for the private key
     * @param non-empty-string $algorithm Signature algorithm (e.g., 'ES256', 'ES384', 'ES512')
     * @param non-empty-string $signingInput The data to be signed (JWS signing input)
     */
    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult
    {
        try {
            $hashAlgorithm = SignatureHashAlgorithm::from($algorithm);
        } catch (ValueError) {
            throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}");
        }

        $privateKey = $this->loadAndValidateEcdsaKey($kid, $hashAlgorithm, KeyRole::Private);

        $signature = $this->signData($signingInput, $privateKey, $algorithm);

        return new SignatureHandlerResult(signature: new JwtSignature($signature));
    }

    /**
     * Verify the bundle’s digital signature using ECDSA.
     *
     * ECDSA verification does not provide reliable error differentiation.
     *
     * OpenSSL may report the same ECDSA verification failure either as a simple
     * "invalid signature" or as a technical error, depending on internal
     * implementation details (version, curve, encoding).
     *
     * Therefore, all non-successful verification results are treated uniformly
     * as a failed signature verification. Detailed OpenSSL errors are not
     * suitable for semantic error handling.
     *
     * @throws InvalidTokenException
     */
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        try {
            $hashAlgorithm = SignatureHashAlgorithm::from($algorithm);
        } catch (ValueError) {
            throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}");
        }

        $publicKey = $this->loadAndValidateEcdsaKey($kid, $hashAlgorithm, KeyRole::Public);

        $verified = openssl_verify(
            data: $aad,
            signature: $signature,
            public_key: $publicKey,
            algorithm: $hashAlgorithm->name
        );

        if ($verified === 1) {
            return;
        }

        $errors = $this->errorHelper->collectErrors();
        $errorsString = implode(' | ', $errors);

        throw new InvalidTokenException(
            sprintf(
                'OpenSSL (kid=%s, alg=%s): %s',
                $kid,
                $hashAlgorithm->name,
                $errorsString === '' ? 'unknown OpenSSL error' : $errorsString
            )
        );
    }

    private function signData(
        string $data,
        #[SensitiveParameter]
        OpenSSLAsymmetricKey $privateKey,
        string $algorithm
    ): string {
        /** @var string|null $signature */
        $signature = null;

        if (openssl_sign($data, $signature, $privateKey, $algorithm) === true && is_string($signature)) {
            return $signature;
        }

        $message = $this->errorHelper->getFormattedErrorMessage('Compute Signature Failed: ');
        throw new SignatureComputationException($message);
    }

    /**
     * Load an EC key and validate its curve against the expected curve for the hash algorithm.
     */
    private function loadAndValidateEcdsaKey(string $kid, SignatureHashAlgorithm $hashAlgorithm, KeyRole $role): OpenSSLAsymmetricKey
    {
        $cacheKey = $this->cacheKey($kid, $role, $hashAlgorithm);
        if (isset($this->validatedKeys[$cacheKey])) {
            return $this->validatedKeys[$cacheKey];
        }

        $key = $this->loadOpensslKey($kid, $role);

        $curveName = $this->extractCurveName($key, $kid);

        if ($curveName !== $hashAlgorithm->ecCurveName()) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid EC curve for [%s]: expected [%s], got [%s].',
                    $kid,
                    $curveName,
                    $hashAlgorithm->ecCurveName()
                )
            );
        }

        return $this->validatedKeys[$cacheKey] = $key;
    }

    private function cacheKey(string $kid, KeyRole $role, SignatureHashAlgorithm $hashAlgorithm): string
    {
        return $kid . '|' . $role->value . '|' . $hashAlgorithm->value;
    }

    private function loadOpensslKey(string $kid, KeyRole $role): OpenSSLAsymmetricKey
    {
        return $role === KeyRole::Public
            ? $this->manager->getPublicKey($kid)
            : $this->manager->getPrivateKey($kid);
    }

    private function extractCurveName(OpenSSLAsymmetricKey $key, string $kid): string
    {
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ! isset($details['ec']) || ! is_array($details['ec'])) {
            throw new InvalidArgumentException(sprintf('Key [%s] is not a valid EC key.', $kid));
        }

        $curve = $details['ec']['curve_name'] ?? null;
        if (! is_string($curve) || $curve === '') {
            throw new InvalidArgumentException(sprintf('Key [%s] has no valid curve name.', $kid));
        }

        return $curve;
    }
}
