<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Config\AlgorithmConfig;
use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureVerificationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Token\Serializer\JwsSigningInput;
use SensitiveParameter;

use function implode;
use function is_array;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_sign;
use function openssl_verify;
use function sprintf;
use function strtolower;

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
     * Create a digital signature over the bundle using ECDSA.
     *
     * @throws SignatureComputationException
     */
    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        $cnf = new AlgorithmConfig($config);

        $kid       = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $cnf->hashAlgorithm();

        $privateKey   = $this->loadAndValidateEcdsaKey($kid, $algorithm, KeyRole::Private);
        $signingInput = JwsSigningInput::fromBundle($bundle);

        $bundle->setSignature(new JwtSignature(
            $this->signData($signingInput, $privateKey, $algorithm)
        ));
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
     * @throws SignatureVerificationException
     */
    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        $cnf = new AlgorithmConfig($config);

        $kid       = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $cnf->hashAlgorithm();

        $publicKey = $this->loadAndValidateEcdsaKey($kid, $algorithm, KeyRole::Public);

        $verified = openssl_verify(
            data: $bundle->getEncryption()->getAad(),
            signature: (string) $bundle->getSignature(),
            public_key: $publicKey,
            algorithm: $cnf->hashAlgorithm()
        );

        if ($verified === 1) {
            return;
        }

        $errors = $this->errorHelper->collectErrors();

        throw new InvalidTokenException(
            sprintf(
                'OpenSSL (kid=%s, alg=%s): %s',
                $kid,
                $algorithm,
                $errors ? implode(' | ', $errors) : 'unknown OpenSSL error'
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

        if (openssl_sign($data, $signature, $privateKey, $algorithm) === true && $signature !== null) {
            return $signature;
        }

        $message = $this->errorHelper->getFormattedErrorMessage('Compute Signature Failed: ');
        throw new SignatureComputationException($message);
    }

    /**
     * Load an EC key and validate its curve against the expected curve for the hash algorithm.
     */
    private function loadAndValidateEcdsaKey(string $kid, string $hashAlgorithm, KeyRole $role): OpenSSLAsymmetricKey
    {
        $cacheKey = $this->cacheKey($kid, $role, $hashAlgorithm);
        if (isset($this->validatedKeys[$cacheKey])) {
            return $this->validatedKeys[$cacheKey];
        }

        $key = $this->loadOpensslKey($kid, $role);

        $curve = $this->extractCurveName($key, $kid);
        $this->assertCurveMatchesAlgorithm($curve, $hashAlgorithm, $kid);

        return $this->validatedKeys[$cacheKey] = $key;
    }

    private function cacheKey(string $kid, KeyRole $role, string $hashAlgorithm): string
    {
        return $kid . '|' . $role->value . '|' . strtolower($hashAlgorithm);
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
        if (!is_array($details) || !isset($details['ec']) || !is_array($details['ec'])) {
            throw new InvalidArgumentException(sprintf('Key [%s] is not a valid EC key.', $kid));
        }

        $curve = $details['ec']['curve_name'] ?? null;
        if (!is_string($curve) || $curve === '') {
            throw new InvalidArgumentException(sprintf('Key [%s] has no valid curve name.', $kid));
        }

        return $curve;
    }

    private function assertCurveMatchesAlgorithm(string $actualCurve, string $hashAlgorithm, string $kid): void
    {
        $expectedCurve = $this->mapHashAlgorithmToCurve($hashAlgorithm);

        if ($actualCurve !== $expectedCurve) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid EC curve for [%s]: expected [%s], got [%s].',
                    $kid,
                    $expectedCurve,
                    $actualCurve
                )
            );
        }
    }

    private function mapHashAlgorithmToCurve(string $hashAlgorithm): string
    {
        return match (strtolower($hashAlgorithm)) {
            'sha256' => 'prime256v1', // ES256
            'sha384' => 'secp384r1',  // ES384
            'sha512' => 'secp521r1',  // ES512 (JWA uses P-521 with SHA-512)
            default => throw new InvalidArgumentException(
                sprintf('Unsupported hash algorithm for EC key: %s.', $hashAlgorithm)
            ),
        };
    }
}
