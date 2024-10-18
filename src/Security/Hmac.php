<?php

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Exception\HashErrorException;
use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Security\HmacAlgorithm;

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
final class Hmac extends HmacAlgorithm
{
    // Error messages for different failure scenarios.
    const ERROR_DATA_EMPTY = "Data cannot be empty.";
    const ERROR_PROVIDED_HMAC_EMPTY = "Signature cannot be empty.";
    const ERROR_SECRET_EMPTY = "Secret cannot be empty.";
    const ERROR_SECRET_TOO_SHORT = 'HMAC key is too short. Expected %s, got %s bytes for the selected algorithm.';

    /**
     * Generates an HMAC signature for the provided data using a secret key.
     *
     * This method generates a cryptographic HMAC signature based on the specified algorithm
     * (e.g., SHA256, SHA384, SHA512) and secret key. Before generating the signature,
     * it validates that the secret key is long enough for the selected algorithm, ensuring
     * it meets the minimum block size requirements. An exception is thrown if the key is too short.
     *
     * @param string $data The data to be signed.
     * @param string &$signature The generated signature is stored by reference in this variable.
     * @param int $length The length of the hashing algorithm (e.g., 256 for SHA256).
     * @param string $secret The secret key used to generate the HMAC signature.
     *
     * @throws InvalidArgumentException If the data or secret key is empty, or if the key is too short
     *                                  for the specified algorithm.
     * @throws InvalidArgumentException If the algorithm is not supported.
     */
    public function signHmac(string $data, string $algorithm, string $secret): string
    {
        $this->validateHmacInput($data, $algorithm, $secret);

        // Generate the HMAC signature using the hash_hmac function.
        return hash_hmac($algorithm, $data, $secret, true);
    }

    /**
     * Verifies an HMAC signature by comparing it to an expected signature.
     *
     * This method calculates the expected HMAC signature for the provided data and compares it
     * with the provided signature using `hash_equals()`, which prevents timing attacks.
     *
     * @param string $data The data that was signed.
     * @param string $providedHmac The signature to verify.
     * @param string $algorithm The algorithm used for HMAC (e.g., sha256).
     * @param string $secret The secret key that was used to generate the signature.
     *
     * @return bool Returns true if the signature is valid, otherwise throws an exception.
     *
     * @throws InvalidArgumentException If the data, signature, algorithm, or secret is invalid.
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
        $this->throwIfTrue(empty($data), self::ERROR_DATA_EMPTY);

        // Ensure the secret key is not empty.
        $this->throwIfTrue(empty($secret), self::ERROR_SECRET_EMPTY);

        // Determine the algorithm based on the length (e.g., sha256, sha384, sha512).
        // Ensure the algorithm is supported.
        $this->throwIfTrue(!in_array($algorithm, $this->getSupportedAlgorithms()), sprintf(self::ERROR_ALGORITHM_UNSUPPORTED, $algorithm));

        // Get the required block size for the selected algorithm.
        $blockSize = $this->getHmacBlockSize($algorithm);

        // Check if the secret key length is sufficient.
        $this->throwIfTrue(strlen($secret) < $blockSize, sprintf(self::ERROR_SECRET_TOO_SHORT, $blockSize, strlen($secret)));
    }

    /**
    * Throws an InvalidArgumentException if the provided condition is true.
    *
    * This method is used to centralize and simplify the logic for checking
    * conditions that should trigger an exception. If the provided boolean
    * expression evaluates to true, an InvalidArgumentException is thrown
    * with the provided error message.
    *
    * @param bool $bool The condition to evaluate. If true, an exception will be thrown.
    * @param string $message The exception message to be used if the condition is true.
    *
    * @throws InvalidArgumentException If the condition evaluates to true.
    */
    private function throwIfTrue(bool $bool, string $message): void
    {
        if (true === $bool) {
            throw new InvalidArgumentException($message);
        }
    }
}
