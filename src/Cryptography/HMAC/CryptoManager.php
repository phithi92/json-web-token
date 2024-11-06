<?php

namespace Phithi92\JsonWebToken\Cryptography\HMAC;

use Phithi92\JsonWebToken\Exception\AlgorithmManager\EmptyFieldException;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\InvalidSecretLengthException;
use Phithi92\JsonWebToken\Cryptography\HMAC\AlgorithmRegistry;

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
final class CryptoManager extends AlgorithmRegistry
{
    // Error messages for different failure scenarios.
    private const ERROR_DATA_EMPTY = "Data cannot be empty.";
    private const ERROR_SECRET_EMPTY = "Secret cannot be empty.";
    private const ERROR_SECRET_TOO_SHORT = 'HMAC key is too short. '
            . 'Expected %s, got %s bytes for the selected algorithm.';

    /**
     * Generates an HMAC signature for the provided data using a secret key.
     *
     * This method generates a cryptographic HMAC signature based on the specified algorithm
     * (e.g., SHA256, SHA384, SHA512) and secret key. Before generating the signature,
     * it validates that the secret key is long enough for the selected algorithm, ensuring
     * it meets the minimum block size requirements. An exception is thrown if the key is too short.
     *
     * @param string $data       The data to be signed.
     * @param string &$signature The generated signature is stored by reference in this variable.
     * @param int    $length     The length of the hashing algorithm (e.g., 256 for SHA256).
     * @param string $secret     The secret key used to generate the HMAC signature.
     *
     */
    public function signHmac(string $data, string $algorithm, string $secret): string
    {
        $this->validateHmacInput($data, $algorithm, $secret);

        // Generate the HMAC signature using the hash_hmac function.
        $hash = hash_hmac($algorithm, $data, $secret, true);

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
     * @param string $secret       The secret key that was used to generate the signature.
     *
     * @return bool Returns true if the signature is valid and false if not.
     */
    public function verifyHmac(string $data, string $providedHmac, string $algorithm, string $secret): bool
    {
        $this->validateHmacInput($data, $algorithm, $secret);

        // Calculate the expected HMAC signature.
        $expectedHash = hash_hmac($algorithm, $data, $secret, true);

        // Perform a timing-safe comparison of the expected and provided signatures.
        return hash_equals($expectedHash, $providedHmac);
    }

    private function validateHmacInput(string $data, string $algorithm, string $secret): void
    {
        // Ensure the data is not empty.
        if (empty($data)) {
            throw new EmptyFieldException('field');
        }

        // Ensure the secret key is not empty.
        if (empty($secret)) {
            throw new EmptyFieldException('secret');
        }

        // Determine the algorithm based on the length (e.g., sha256, sha384, sha512).
        // Ensure the algorithm is supported.
        if (!in_array($algorithm, $this->getSupportedAlgorithms())) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        // Get the required block size for the selected algorithm.
        $blockSize = $this->getHmacBlockSize($algorithm);

        // Check if the secret key length is sufficient.
        if (strlen($secret) < $blockSize) {
            throw new InvalidSecretLengthException(strlen($secret), $blockSize);
        }
    }

    // Cached list of supported algorithms, initialized lazily.
    private ?array $supportedAlgorithms = null;

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
        if ($this->supportedAlgorithms === null) {
            $this->supportedAlgorithms = hash_hmac_algos();
        }

        return $this->supportedAlgorithms;
    }
}
