<?php

namespace Phithi92\JsonWebToken\Cryptographys\HMAC;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidSecretLengthException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingPassphraseException;
use Phithi92\JsonWebToken\Cryptographys\HMAC\AlgorithmsTrait;
use Phithi92\JsonWebToken\Cryptographys\Provider;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

/**
 * Hmac class for generating and verifying HMAC signatures and tags.
 *
 * This class provides functionality for generating and verifying HMAC signatures using
 * multiple supported algorithms such as SHA256, SHA384, and SHA512. It also includes
 * methods for generating and verifying HMAC tags in JSON Web Tokens (JWT).
 *
 * Key aspects:
 * - Validates data, secrets, and algorithms.
 * - Ensures key length is appropriate for the chosen algorithm.
 * - Implements timing attack-resistant comparisons using `hash_equals()`.
 *
 * Errors are handled using exceptions to ensure clarity and security in case of failures.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
final class CryptographyProdvider extends Provider
{
    use AlgorithmsTrait;

    // Cached list of supported algorithms, initialized lazily.
    private array $supportedAlgorithms;

    public function __construct(JwtAlgorithmManager $manager)
    {
        parent::__construct($manager);
        $this->setSupportedAlgorithms(hash_hmac_algos());
    }

    /**
     * Retrieves the list of supported HMAC algorithms.
     *
     * This method lazily initializes and caches the list of supported algorithms using
     * PHP's `hash_hmac_algos()` function.
     *
     * @return array The list of supported algorithms.
     */
    public function getSupportedAlgorithms(): array
    {
        return $this->supportedAlgorithms;
    }

    private function setSupportedAlgorithms(array $algorithms): self
    {
        $this->supportedAlgorithms = $algorithms;
        return $this;
    }

    /**
     * Generates an HMAC signature for the provided data using a secret key.
     *
     * This method generates a cryptographic HMAC signature based on the specified algorithm
     * (e.g., SHA256, SHA384, SHA512) and secret key. Before generating the signature,
     * it validates that the secret key is long enough for the selected algorithm, ensuring
     * it meets the minimum block size requirements. An exception is thrown if the key is too short.
     *
     * @param string $data      The data to be signed.
     * @param string $algorithm The algorithm
     */
    public function signHmac(string $data, string $algorithm): string
    {
        $this->validateHmacInput($data, $algorithm);

        // Generate the HMAC signature using the hash_hmac function.
        $hash = hash_hmac($algorithm, $data, $this->getPassphrase(), true);

        //        var_dump($hash,hash($algorithm, '', false));exit;
        //
        //        $expectedLength = strlen(hash($algorithm, '', false));  // Länge eines leeren Hashes
        //        if (strlen($hash) !== $expectedLength) {
        //            throw new InvalidArgument('HMAC computation failed.');
        //        }

        return $hash;
    }

    /**
     * Verifies an HMAC signature by comparing it to an expected signature.
     *
     * This method calculates the expected HMAC signature for the provided data and compares it
     * with the provided signature using `hash_equals()`, which prevents timing attacks.
     *
     * @param string $data         The data that was signed.
     * @param string $providedHmac The signature to verify.
     * @param string $algorithm    The algorithm used for HMAC (e.g., sha256).
     *
     * @return bool Returns true if the signature is valid and false if not.
     */
    public function verifyHmac(string $data, string $providedHmac, string $algorithm): bool
    {
        $this->validateHmacInput($data, $algorithm);

        // Calculate the expected HMAC signature.
        $expectedHash = hash_hmac($algorithm, $data, $this->getPassphrase(), true);

        // Perform a timing-safe comparison of the expected and provided signatures.
        return hash_equals($expectedHash, $providedHmac);
    }

    /**
     * Validates the input parameters for HMAC generation.
     *
     * This method checks that the provided data, algorithm, and secret key meet
     * necessary conditions for HMAC operations. It ensures that the data and secret
     * key are non-empty, that the specified algorithm is supported, and that the
     * secret key length meets the minimum required block size for the algorithm.
     *
     * @param string $data      The data to be hashed using HMAC.
     * @param string $algorithm The hashing algorithm to use (e.g., sha256, sha384, sha512).
     *
     * @throws EmptyFieldException If the data or secret key is empty.
     * @throws UnsupportedAlgorithmException If the specified algorithm is not supported.
     * @throws InvalidSecretLengthException If the secret key length is less than the required block size.
     *
     * @return void
     */
    private function validateHmacInput(string $data, string $algorithm): void
    {

        // Ensure the data is not empty.
        if (empty($data)) {
            throw new EmptyFieldException('field');
        }

        // Ensure the secret key is not empty or null.
        if (empty($this->getPassphrase())) {
            throw new MissingPassphraseException();
        }

        // Determine the algorithm based on the length (e.g., sha256, sha384, sha512).
        // Ensure the algorithm is supported.
        if (!in_array($algorithm, $this->getSupportedAlgorithms())) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        // Get the required block size for the selected algorithm.
        $blockSize = $this->getHmacBlockSize($algorithm);
        $passphraseLength = strlen($this->getPassphrase());

        // Check if the secret key length is sufficient.
        if ($passphraseLength < $blockSize) {
            throw new InvalidSecretLengthException($passphraseLength, $blockSize);
        }
    }

    /**
     * Retrieves the block size for the given HMAC algorithm.
     *
     * This method returns the block size associated with the selected HMAC algorithm.
     * If the algorithm is unsupported, it throws an exception.
     *
     * @param string $algorithm The HMAC algorithm (e.g., 'sha256').
     *
     * @return int The block size in bytes.
     *
     * @throws UnsupportedAlgorithmException If the algorithm is not supported.
     */
    protected function getHmacBlockSize(string $algorithm): int
    {
        // Ensure the algorithm is in lowercase.
        $algorithm = strtolower($algorithm);

        // Return the block size for the known algorithm or throw an exception if unsupported.
        if (isset($this->blockSizes[$algorithm])) {
            return $this->blockSizes[$algorithm];
        }

        throw new UnsupportedAlgorithmException($algorithm);
    }
}
