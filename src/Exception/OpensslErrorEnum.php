<?php

namespace Phithi92\JsonWebToken\Exception;

enum OpensslErrorEnum: string
{
    public const UNSUPPORTED_ALGORITHM = 'Algorithm %s not supported';

    // Constants for signature-related error messages
    public const SIGNATURE_VERIFICATION_FAILED = 'Signature verification failed with algorithm: %s.';
    public const SIGNATURE_CREATION_FAILED = 'Signature creation failed with algorithm: %s.';

    // Constants for cipher-related error messages
    public const CIPHER_DECRYPTION_FAILED = 'Decryption failed with algorithm: %s.';
    public const CIPHER_ENCRYPTION_FAILED = 'Encryption failed with algorithm: %s.';
    public const CIPHER_EMPTY_RESULT = 'Cipher failed. Empty result with algorithm: %s.';

    // Constant for OpenSSL key-related error messages
    public const OPENSSL_DECRYPT_FAILED = 'Decryption failed for algorithm %s. Error: %s';
    public const OPENSSL_ENCRYPT_FAILED = 'Encryption failed for algorithm %s. Error: %s';
    public const OPENSSL_EMPTY_RESULT = 'Cipher failed - Empty result for algorithm %s. Error: %s';

    public const OPENSSL_INVALID_PUBLIC_KEY = 'Invalid public key: %s';
    public const OPENSSL_INVALID_PRIVATE_KEY = 'Invalid private key: %s';

    // OpenSSL RSA
    public const OPENSSL_PUBLIC_KEY_DECRYPT_FAILED = 'Decryption using the private key failed for algorithm: %s.';
    public const OPENSSL_PUBLIC_KEY_ENCRYPT_FAILED = 'Encryption using the private key failed for algorithm: %s.';
    public const OPENSSL_PRIVATE_KEY_ENCRYPTION_FAILED
            = 'Encryption using the private key failed for algorithm: %s.';
    public const OPENSSL_PRIVATE_KEY_DECRYPTION_FAILED
            = 'Decryption using the private key failed for algorithm: %s.';
}
