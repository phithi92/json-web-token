<?php

namespace Phithi92\JsonWebToken\Exception;

use Phithi92\JsonWebToken\Exception\OpensslErrorEnum;
use Exception;

class OpensslError extends Exception
{
    /**
     * Generates an exception for unsupported algorithm usage.
     *
     * @param  string $algorithm - The unsupported algorithm used.
     * @return self
     */
    public static function unsupportedAlgorithm(string $algorithm): self
    {
        $message = sprintf(OpensslErrorEnum::UNSUPPORTED_ALGORITHM, $algorithm);
        return self::generateException($message);
    }

    /**
     * Generates an exception for encryption failure with the provided algorithm.
     *
     * @param  string $cipher - The encryption algorithm that failed.
     * @return self
     */
    public static function cipherEncryptionFailed(string $cipher): self
    {
        $message = sprintf(OpensslErrorEnum::CIPHER_ENCRYPTION_FAILED, $cipher);
        return self::generateException($message);
    }

    /**
     * Generates an exception for decryption failure with the provided algorithm.
     *
     * @param  string $cipher - The decryption algorithm that failed.
     * @return self
     */
    public static function cipherDecryptionFailed(string $cipher): self
    {
        $message = sprintf(OpensslErrorEnum::CIPHER_DECRYPTION_FAILED, $cipher);
        return self::generateException($message);
    }

    /**
     * Generates an exception when a cipher operation produces an empty result.
     *
     * @param  string $cipher - The cipher algorithm that returned an empty result.
     * @return self
     */
    public static function cipherEmptyResult(string $cipher): self
    {
        $message = sprintf(OpensslErrorEnum::CIPHER_EMPTY_RESULT, $cipher);
        return self::generateException($message);
    }

    /**
     * Generates an exception for signature creation failure with the provided algorithm.
     *
     * @param  string $algorithm - The signature algorithm that failed.
     * @return self
     */
    public static function signatureCreationFailed(string $algorithm): self
    {
        $message = sprintf(OpensslErrorEnum::SIGNATURE_CREATION_FAILED, $algorithm);
        return self::generateException($message);
    }

    /**
     * Generates an exception for signature verification failure with the provided algorithm.
     *
     * @param  string $algorithm - The signature algorithm that failed during verification.
     * @return self
     */
    public static function signatureVerificationFailed(string $algorithm): self
    {
        $message = sprintf(OpensslErrorEnum::SIGNATURE_VERIFICATION_FAILED, $algorithm);
        return self::generateException($message);
    }

    /**
     * Generates an exception for an invalid private key.
     *
     * @return self
     */
    public static function opensslPrivateKeyInvalid(): self
    {
        return self::generateException(OpensslErrorEnum::OPENSSL_INVALID_PRIVATE_KEY);
    }

    /**
     * Generates an exception for an invalid public key.
     *
     * @return self
     */
    public static function opensslPublicKeyInvalid(): self
    {
        return self::generateException(OpensslErrorEnum::OPENSSL_INVALID_PUBLIC_KEY);
    }

    /**
     * Generates an exception when private key decryption fails.
     *
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslPrivateKeyDecryptFailed(string $errorMessage): self
    {
        return self::opensslOperationFailed(
            OpensslErrorEnum::OPENSSL_PRIVATE_KEY_DECRYPT_FAILED,
            'private',
            $errorMessage
        );
    }

    /**
     * Generates an exception when private key encryption fails.
     *
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslPrivateKeyEncryptFailed(string $errorMessage): self
    {
        return self::opensslOperationFailed(
            OpensslErrorEnum::OPENSSL_PRIVATE_KEY_ENCRYPT_FAILED,
            'private',
            $errorMessage
        );
    }

    /**
     * Generates an exception when public key decryption fails.
     *
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslPublicKeyDecryptFailed(string $errorMessage): self
    {
        return self::opensslOperationFailed(
            OpensslErrorEnum::OPENSSL_PUBLIC_KEY_DECRYPT_FAILED,
            'public',
            $errorMessage
        );
    }

    /**
     * Generates an exception when public key encryption fails.
     *
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslPublicKeyEncryptFailed(string $errorMessage): self
    {
        return self::opensslOperationFailed(
            OpensslErrorEnum::OPENSSL_PUBLIC_KEY_ENCRYPT_FAILED,
            'public',
            $errorMessage
        );
    }

    /**
     * Generates an exception when OpenSSL encryption fails.
     *
     * @param  string $algo         - The encryption algorithm used.
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslEncryptFailed(string $algo, string $errorMessage): self
    {
        $message = sprintf(OpensslErrorEnum::OPENSSL_ENCRYPT_FAILED, $algo, $errorMessage);
        return self::generateException($message);
    }

    /**
     * Generates an exception when OpenSSL decryption fails.
     *
     * @param  string $algo         - The decryption algorithm used.
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslDecryptFailed(string $algo, string $errorMessage): self
    {
        $message = sprintf(OpensslErrorEnum::OPENSSL_DECRYPT_FAILED, $algo, $errorMessage);
        return self::generateException($message);
    }

    /**
     * Generates an exception when an OpenSSL operation returns an empty result.
     *
     * @param  string $algo         - The algorithm used.
     * @param  string $errorMessage - The error message detailing the failure.
     * @return self
     */
    public static function opensslEmptyResult(string $algo, string $errorMessage): self
    {
        $message = sprintf(OpensslErrorEnum::OPENSSL_EMPTY_RESULT, $algo, $errorMessage);
        return self::generateException($message);
    }

    /**
     * Helper method to create a new exception instance.
     *
     * @param  string $message - The error message for the exception.
     * @return self
     */
    private static function generateException(string $message): self
    {
        return new self($message);
    }

    /**
     * Consolidated method for OpenSSL operation failures.
     *
     * @param  string $operationEnum - The error message template from CipherErrorEnum.
     * @param  string $keyType       - The key type involved (private or public).
     * @param  string $errorMessage  - Additional error details.
     * @return self
     */
    private static function opensslOperationFailed(string $operationEnum, string $keyType, string $errorMessage): self
    {
        $message = sprintf($operationEnum, $keyType, $errorMessage);
        return self::generateException($message);
    }
}
