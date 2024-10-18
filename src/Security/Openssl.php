<?php

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\CipherErrorException;
use Phithi92\JsonWebToken\Security\OpensslAlgorithm;
use OpenSSLAsymmetricKey;

use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;
use function openssl_private_decrypt;
use function openssl_private_encrypt;
use function openssl_pkey_get_private;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_get_cipher_methods;
use function openssl_cipher_iv_length;
use function openssl_cipher_key_length;

/**
 * Openssl is a final class that extends OpensslAlgorithm and provides encryption,
 * decryption, key management, and signature functionalities using the OpenSSL library.
 *
 * This class supports both symmetric (AES) and asymmetric (RSA, ECDSA) encryption
 * mechanisms and also includes functionalities for secure key exchanges using
 * Elliptic Curve Diffie-Hellman (ECDH). Additionally, it offers methods for signing
 * and verifying data using RSA and ECDSA, as well as advanced cryptographic techniques
 * like AES-GCM for authenticated encryption.
 *
 * Key functionalities include:
 * - Managing RSA and ECDSA public and private keys.
 * - Symmetric encryption and decryption using AES with GCM mode for authentication.
 * - Asymmetric encryption and decryption using RSA with support for various padding schemes.
 * - Signing and verifying data using RSA-PSS, ECDSA, and other algorithms.
 * - Secure key exchange using ECDH for key agreement protocols.
 * - Error handling and validation for ciphers, passphrases, and initialization vectors (IV).
 *
 * The class provides several constants for error messages and handles memory cleanup
 * by ensuring keys are explicitly deleted during object destruction.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
final class Openssl extends OpensslAlgorithm
{
    // Error messages for various encryption and decryption failure scenarios
    const ERROR_DECRYPTION_EMPTY_RESULT = 'Decryption failed. Unexpected empty result';
    const ERROR_DECRYPTION_FAILS = 'Decryption failed: %s';
    const ERROR_ENCRYPTION_EMPTY_RESULT = 'Encryption failed. Unexpected empty result';
    const ERROR_ENCRYPTION_FAILS = 'Encryption failed: %s';
    const ERROR_INVALID_PUBLIC_KEY = 'Invalid public key: %s';
    const ERROR_INVALID_PRIVATE_KEY = 'Invalid private key: %s';
    const ERROR_INVALID_PRIVATE_KEY_DETAILS = 'Error. Cant read private key propertys';
    const ERROR_INVALID_IV = 'Invalid IV length %s bytes but %s bytes expexted.';
    const ERROR_INVALID_KEY_LENGTH = 'Invalid key length %s bytes but %s bytes expexted.';
    const ERROR_INVALID_CIPHER = 'Invalid cipher "%s".';
    const ERROR_INVALID_PASSPHRASE = 'Invalid Passphrase. Expect %s bytes but %s bytes given.';
    const ERROR_INVALID_OUTPUT = 'Output variable need to be empty';
    const ERROR_EMPTY_DATA = 'The data cannot be empty.';
    const ERROR_SIGN = 'RSA signing failed. %s';
    const ERROR_ALGORITHM_UNSUPPORTED = 'Unsupported algorithm %s';

    private ?OpenSSLAsymmetricKey $publicKey = null;
    private ?OpenSSLAsymmetricKey $privateKey = null;

    /**
     * Padding information for various OpenSSL padding schemes.
     * Defines the number of bytes added by different padding types.
     */

    // Destructor ensures that the keys are explicitly deleted
    public function __destruct()
    {
        if ($this->privateKey !== null) {
            $this->privateKey = null;             // Nullify the reference
        }

        if ($this->publicKey !== null) {
            $this->publicKey = null;              // Nullify the reference
        }
    }

    /**
     * Sets the public key.
     *
     * @param string $key The public key in string format.
     * @return self
     * @throws InvalidArgumentException if the provided key is invalid.
     */
    public function setPublicKey(string $key): self
    {
        // Attempt to load the public key using OpenSSL
        $publicKey = openssl_pkey_get_public($key);

        // If the key is invalid, throw an exception
        if (!$publicKey) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_PUBLIC_KEY, $key));
        }

        // Store the public key in the class property
        $this->publicKey = $publicKey;

        return $this;
    }

    /**
    * Retrieves the public key.
    *
    * @return ?OpenSSLAsymmetricKey The loaded public key.
    */
    public function getPublicKey(): ?OpenSSLAsymmetricKey
    {
        // Return the stored public key
        return $this->publicKey;
    }

    /**
     * Sets the private key.
     *
     * @param string $key The private key in string format.
     * @return self
     * @throws InvalidArgumentException if the provided key is invalid.
     */
    public function setPrivateKey(string $key): self
    {
        // Attempt to load the private key using OpenSSL
        $privateKey = openssl_pkey_get_private($key);

        // If the key is invalid, throw an exception
        if (!$privateKey) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_PRIVATE_KEY, $key));
        }

        // Store the private key in the class property
        $this->privateKey = $privateKey;

        return $this;
    }

    /**
    * Retrieves the private key.
    *
    * @return ?OpenSSLAsymmetricKey The loaded private key.
    */
    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        // Return the stored private key
        return $this->privateKey;
    }


    /**
     * Decrypts data using a passphrase and AES cipher.
     *
     * @param string $data The encrypted data to be decrypted.
     * @param string &$decrypted_data Reference to the output of decrypted data.
     * @param string $cipher The encryption algorithm (e.g., AES-256-CBC).
     * @param string $passphrase The secret key used for decryption.
     * @param string $iv The initialization vector used in encryption.
     * @param string|null $tag (Optional) The authentication tag for verifying integrity.
     *
     * @throws InvalidArgumentException if IV length is incorrect.
     * @throws CipherErrorException if decryption fails.
     */
    public function decryptWithPassphrase(string $data, string &$decrypted_data, string $cipher, string $passphrase, string $iv, ?string $tag = null): void
    {
        $this->validateInputOutputData($data, $decrypted_data);

        $this->validateCipher($cipher, $passphrase, $iv);

        // Decrypt data with AES and optional tag for integrity checking
        $decrypted_data = openssl_decrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted_data === false) {
            throw new CipherErrorException(sprintf(self::ERROR_DECRYPTION_FAILS, openssl_error_string()));
        }

        if (empty($decrypted_data)) {
            throw new CipherErrorException(self::ERROR_DECRYPTION_EMPTY_RESULT);
        }
    }

    /**
     * Encrypts data using a passphrase and AES cipher.
     *
     * @param string $data The data to be encrypted.
     * @param string &$cipher_data Reference to the output of encrypted data.
     * @param string $cipher The encryption algorithm (e.g., AES-256-CBC).
     * @param string $passphrase The secret key used for encryption.
     * @param string $iv The initialization vector used in encryption.
     * @param string &$tag Reference to the authentication tag generated for integrity.
     *
     * @throws InvalidArgumentException if any argument is empty.
     * @throws CipherErrorException if encryption fails.
     */
    public function encryptWithPassphrase(string $data, string &$encrypted_data, string $cipher, string $passphrase, string $iv, string &$tag): void
    {
        // Validate input parameters
        $this->validateInputOutputData($data, $encrypted_data);

        $this->validateCipher($cipher, $passphrase, $iv);

        // Encrypt data with AES and generate an authentication tag
        $encrypted_data = openssl_encrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted_data === false) {
            throw new CipherErrorException(sprintf(self::ERROR_ENCRYPTION_FAILS, openssl_error_string()));
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted_data)) {
            throw new CipherErrorException(self::ERROR_ENCRYPTION_EMPTY_RESULT);
        }
    }

    /**
     * Decrypts data using a private RSA key.
     *
     * @param string $data The encrypted data to be decrypted.
     * @param string &$decrypted_data Reference to the output of decrypted data.
     * @param string $private_pem The private key in PEM format.
     * @param int $padding The padding algorithm used during encryption.
     *
     * @throws InvalidArgumentException if the private key is invalid.
     * @throws CipherErrorException if decryption fails.
     */
    public function rsaDecryptWithPrivateKey(string $data, string &$decrypted_data, int $padding): void
    {
        $this->validateInputOutputData($data, $decrypted_data);

        // Retrieve the private key from PEM string
        $private_key = $this->getPrivateKey();

        // Initialize decrypted data variable
        $decrypted_data = '';

        // Decrypt data with RSA private key
        if (!openssl_private_decrypt($data, $decrypted_data, $private_key, $padding)) {
            throw new CipherErrorException(sprintf(self::ERROR_DECRYPTION_FAILS, openssl_error_string()));
        }

        // Result may be empty if decryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($decrypted_data)) {
            throw new CipherErrorException(self::ERROR_DECRYPTION_EMPTY_RESULT);
        }
    }

    /**
     * Encrypts data using a public RSA key.
     *
     * @param string $data The data to be encrypted.
     * @param string &$encrypted_data Reference to the output of encrypted data.
     * @param string $public_pem The public key in PEM format.
     * @param int $padding The padding algorithm used during encryption.
     *
     * @throws InvalidArgumentException if the public key is invalid.
     * @throws CipherErrorException if encryption fails.
     */
    public function rsaEncryptWithPublicKey(string $data, string &$encrypted_data, int $padding): void
    {
        $this->validateInputOutputData($data, $encrypted_data);

        // Retrieve the public key from PEM string
        $public_key = $this->getPublicKey();

        // Encrypt data with RSA public key
        if (!openssl_public_encrypt($data, $encrypted_data, $public_key, $padding)) {
            throw new CipherErrorException(sprintf(self::ERROR_ENCRYPTION_FAILS, openssl_error_string()));
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted_data)) {
            throw new CipherErrorException(self::ERROR_ENCRYPTION_EMPTY_RESULT);
        }
    }

    /**
    * Performs ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static) key agreement.
    *
    * @param string $algo The hashing algorithm to use for key derivation, defaults to 'sha256'.
    * @return string The derived shared key after hashing.
    */
    public function ecdhEsKeyAgreement(string $algo = 'sha256'): string
    {
       // Retrieve and verify the public key from PEM format
        $public_key = $this->getPublicKey();

       // Retrieve and verify the private key from PEM format
        $private_key = $this->getPrivateKey();

       // Compute the shared secret using ECDH (Elliptic Curve Diffie-Hellman)
        $sharedSecret = openssl_pkey_derive($public_key, $private_key);

       // Perform key derivation or hashing on the shared secret using the specified algorithm
        return hash($algo, $sharedSecret, true); // Example of a KDF (Key Derivation Function) step
    }

    /**
    * Encrypts a key using the PBES2 (Password-Based Encryption Scheme 2) method.
    *
    * @param string $password The password to derive the encryption key.
    * @param string $key The key to be encrypted.
    * @param string|null $salt Optional salt for the key derivation, if not provided, a random salt will be generated.
    * @param int $iterations Number of iterations for the PBKDF2 function, defaults to 10000.
    * @param string $algorithm The encryption algorithm to use, defaults to 'aes-256-cbc'.
    * @return string The encrypted key, base64-encoded, along with the salt and IV.
    * @throws Exception If the encryption process fails.
    */
    public function pbes2EncryptKey(string $password, string $key, string $salt = null, int $iterations = 10000, string $algorithm = 'aes-256-cbc'): string
    {
       // Generate a random salt if none is provided
        if ($salt === null) {
            $salt = openssl_random_pseudo_bytes(16);
        }

       // Derive a key using PBKDF2 (Password-Based Key Derivation Function 2) with the given salt and iterations
        $derivedKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);

       // Get the IV (Initialization Vector) length for the chosen algorithm
        $ivLength = openssl_cipher_iv_length($algorithm);
       // Generate a random IV for encryption
        $iv = openssl_random_pseudo_bytes($ivLength);

       // Encrypt the key using the derived key and IV
        $encryptedKey = openssl_encrypt($key, $algorithm, $derivedKey, 0, $iv);

       // If encryption fails, throw an exception
        if ($encryptedKey === false) {
            throw new CipherErrorException('Encryption failed');
        }

       // Concatenate salt, IV, and the encrypted key, and encode them in base64
        return base64_encode($salt . $iv . $encryptedKey);
    }

    /**
    * Encrypts a message using AES in GCM mode.
    *
    * @param string $plaintext The plaintext message to be encrypted
    * @param string $key The symmetric encryption key
    * @param int $bitLength The length of the key (128, 192, or 256 bits)
    * @param string $iv The initialization vector (IV)
    * @param string $authTag The authentication tag (generated by the function)
    * @param int $tagLength The length of the authentication tag (default is 16 bytes)
    * @return string The encrypted ciphertext
    * @throws Exception On encryption failure
    */
    function aesGcmEncrypt(string $plaintext, string $key, int $bitLength, string &$iv, string &$authTag, int $tagLength = 16): string
    {
        // IV for GCM must be 12 bytes long (recommended for AES-GCM)
        $ivLength = 12;

        // Generate a random IV if none is provided
        if (empty($iv)) {
            $iv = openssl_random_pseudo_bytes($ivLength);
        }

        // Determine the cipher algorithm based on key length (e.g., aes-128-gcm, aes-256-gcm)
        $cipherAlgo = 'aes-' . $bitLength . '-gcm';

        // Encrypt the message in GCM mode
        $ciphertext = openssl_encrypt(
            $plaintext,        // The plaintext message
            $cipherAlgo,       // The AES-GCM cipher algorithm
            $key,              // The encryption key
            OPENSSL_RAW_DATA,  // Use raw binary data for output
            $iv,               // The initialization vector (IV)
            $authTag,          // The authentication tag (generated by the function)
            '',                // Additional authenticated data (optional, empty in this case)
            $tagLength         // The length of the authentication tag (default 16 bytes)
        );

        // Error handling
        if ($ciphertext === false) {
            throw new CipherErrorException('Encryption with AES-GCM failed.');
        }

        return $ciphertext;
    }

   /**
    * Decrypts a message using AES in GCM mode.
    *
    * @param string $ciphertext The encrypted message (ciphertext)
    * @param string $key The symmetric key used for decryption
    * @param int $bitLength The length of the key (128, 192, or 256 bits)
    * @param string $iv The initialization vector (IV)
    * @param string $authTag The authentication tag (to verify integrity)
    * @return string The decrypted plaintext
    * @throws Exception If decryption fails or the authentication tag is invalid
    */
    public function aesGcmDecrypt(string $ciphertext, string $key, int $bitLength, string $iv, string $authTag): string
    {
        // Determine the cipher algorithm based on the key length (e.g., aes-128-gcm, aes-256-gcm)
        $cipherAlgo = 'aes-' . $bitLength . '-gcm';

        // Perform AES-GCM decryption
        $plaintext = openssl_decrypt(
            $ciphertext,        // The ciphertext to decrypt
            $cipherAlgo,        // The AES-GCM algorithm
            $key,               // The symmetric decryption key
            OPENSSL_RAW_DATA,   // Use raw data output
            $iv,                // The initialization vector (IV)
            $authTag            // The authentication tag
        );

        // Check for errors
        if ($plaintext === false) {
            throw new CipherErrorException('Decryption with AES-GCM failed or the authentication tag is invalid.');
        }

        return $plaintext;
    }

    function encryptWithECDH_ES_P521($payload, $recipientPublicKey)
    {
        // Erstelle ein temporäres Schlüsselpaar (Ephemeral Key)
        $ephemeralKey = openssl_pkey_new(['curve_name' => 'P-521', 'private_key_type' => OPENSSL_KEYTYPE_EC]);

        // Extrahiere den öffentlichen Schlüssel
        $ephemeralDetails = openssl_pkey_get_details($ephemeralKey);
        $ephemeralPublicKey = $ephemeralDetails['key'];

        // Berechne das geteilte Geheimnis zwischen dem temporären privaten und dem Empfängeröffentlichen Schlüssel
        openssl_pkey_export($ephemeralKey, $ephemeralPrivateKey);
        $sharedSecret = openssl_dh_compute_key($recipientPublicKey, $ephemeralKey);

        // Der sharedSecret kann jetzt mit einem symmetrischen Verschlüsselungsalgorithmus verwendet werden (z.B. AES-GCM)
        $key = hash('sha256', $sharedSecret, true);

        // AES-GCM verwenden, um den Payload zu verschlüsseln
        $iv = openssl_random_pseudo_bytes(12);
        $ciphertext = openssl_encrypt($payload, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

        return [
            'ciphertext' => base64_encode($ciphertext),
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ephemeralPublicKey' => $ephemeralPublicKey
        ];
    }

    function decryptWithECDH_ES_P521($ciphertext, $iv, $tag, $ephemeralPublicKey, $recipientPrivateKey)
    {
        // Berechne das geteilte Geheimnis zwischen dem Empfängerprivaten und dem Ephemeral-öffentlichen Schlüssel
        $sharedSecret = openssl_dh_compute_key($ephemeralPublicKey, $recipientPrivateKey);

        // Symmetrischen Schlüssel generieren
        $key = hash('sha256', $sharedSecret, true);

        // Entschlüsseln mit AES-GCM
        $plaintext = openssl_decrypt(base64_decode($ciphertext), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, base64_decode($iv), base64_decode($tag));

        return $plaintext;
    }

    /**
    * Generic method to sign data using a private key.
    *
    * This method signs the given data using the specified algorithm and private key.
    * It validates the private key, checks the key length, and applies optional padding (such as RSA-PSS)
    * before performing the signing operation.
    *
    * @param string $data The data to be signed.
    * @param string &$signature The variable to store the generated signature.
    * @param string $algorithm The algorithm to use for signing (e.g., 'SHA256', 'RSA-PSS').
    * @param string $private_pem The private key in PEM format.
    * @param int|null $padding Optional padding parameter for algorithms like RSA-PSS.
    *
    * @throws CipherErrorException If there are issues with the private key or the signing process.
    * @throws InvalidArgumentException If the key length is invalid.
    */
    public function signWithAlgorithm(string $data, string &$signature, string $algorithm, string $private_pem, ?int $padding = null): void
    {
        $this->validateInputOutputData($data, $signature);

        // Retrieve and validate private key
        $private_key = $this->getPrivateKey();

        // Get key details
        $key_details = openssl_pkey_get_details($private_key);
        if (!$key_details || !isset($key_details['bits'])) {
            throw new CipherErrorException(self::ERROR_INVALID_PRIVATE_KEY_DETAILS);
        }

        [$type, $length] = $this->extractAlgorithmComponents($algorithm);

        // Validate key length
        $key_length = $key_details['bits'] / 8;
        if ($key_length > $length) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_KEY_LENGTH, $key_length, $length));
        }

        // Directly sign the data using the private key and algorithm
        if (!openssl_sign($data, $signature, $private_key, $algorithm)) {
            throw new CipherErrorException(sprintf(self::ERROR_SIGN, openssl_error_string()));
        }
    }

    /**
    * Signs data using RSA-PSS with the same logic as RSA.
    *
    * @param string $data The data to be signed.
    * @param string &$signature The variable to store the generated signature.
    * @param string $algorithm The signing algorithm to be used.
    * @param string $private_pem The private RSA key in PEM format.
    *
    * @see signWithAlgorithm
    */
    public function signRsa(string $data, string &$signature, string $algorithm, string $private_pem): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm, $private_pem);
    }

    /**
    * Signs data using RSA-PSS with the same logic as RSA.
    *
    * @param string $data The data to be signed.
    * @param string &$signature The variable to store the generated signature.
    * @param string $algorithm The signing algorithm to be used.
    * @param string $private_pem The private RSA key in PEM format.
    *
    * @see signWithAlgorithm
    */
    public function signRsaPss(string $data, string &$signature, string $algorithm, string $private_pem): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm, $private_pem, OPENSSL_PKCS1_PADDING);
    }

    /**
    * Signs data using ECDSA with the same logic as RSA.
    *
    * @param string $data The data to be signed.
    * @param string &$signature The variable to store the generated signature.
    * @param string $algorithm The signing algorithm to be used.
    * @param string $private_pem The private ECDSA key in PEM format.
    *
    * @see signWithAlgorithm
    */
    public function signEcdsa(string $data, string &$signature, string $algorithm, string $private_pem): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm, $private_pem);
    }

    /**
    * Generic method to verify a signature using a public key.
    *
    * This method verifies the signature for the given data using the specified public key and algorithm.
    *
    * @param string $data The original data that was signed.
    * @param string $signature The signature that needs to be verified.
    * @param string $public_pem The public key in PEM format.
    * @param string $algorithm The algorithm used for signing (e.g., 'SHA256', 'RSA-PSS').
    *
    * @throws CipherErrorException If there are issues with the public key or the verification process.
    * @throws InvalidArgumentException If the input data or key is invalid.
    *
    * @return bool True if the signature is valid, false otherwise.
    */
    public function verifyWithAlgorithm(string $data, string $signature, string $public_pem, string $algorithm): bool
    {
        // Validate inputs (data and signature should not be empty)
        if (empty($data) || empty($signature)) {
            throw new InvalidArgumentException(self::ERROR_EMPTY_DATA);
        }

        // Retrieve and validate the public key
        $public_key = $this->getPublicKey();

        // Verify the signature using the public key and algorithm
        $verification_result = openssl_verify($data, $signature, $public_key, $algorithm);

        // If the verification failed, throw an exception
        if ($verification_result === -1) {
            throw new CipherErrorException(sprintf(self::ERROR_SIGN, openssl_error_string()));
        }

        // Return true if the signature is valid, otherwise false
        return $verification_result === 1;
    }

    /**
     * Verifies an RSA signature using a public key.
     *
     * This method verifies the signature for the given data using RSA and the specified public key.
     *
     * @param string $data The original data that was signed.
     * @param string $signature The signature that needs to be verified.
     * @param string $public_pem The public key in PEM format.
     * @param string $algorithm The hashing algorithm used for signing (e.g., 'SHA256').
     *
     * @throws CipherErrorException If there are issues with the public key or the verification process.
     * @throws InvalidArgumentException If the input data or key is invalid.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyRsa(string $data, string $signature, string $public_pem, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $public_pem, $algorithm);
    }

    /**
    * Verifies an ECDSA signature using a public key.
    *
    * This method verifies the signature for the given data using ECDSA and the specified public key.
    *
    * @param string $data The original data that was signed.
    * @param string $signature The signature that needs to be verified.
    * @param string $public_pem The public ECDSA key in PEM format.
    * @param string $algorithm The hashing algorithm used for signing (e.g., 'SHA256').
    *
    * @throws CipherErrorException If there are issues with the public key or the verification process.
    * @throws InvalidArgumentException If the input data or key is invalid.
    *
    * @return bool True if the signature is valid, false otherwise.
    */
    public function verifyEcdsa(string $data, string $signature, string $public_pem, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $public_pem, $algorithm);
    }

    /**
    * Verifies an RSA-PSS signature using a public key.
    *
    * This method verifies the signature for the given data using RSA-PSS and the specified public key.
    *
    * @param string $data The original data that was signed.
    * @param string $signature The signature that needs to be verified.
    * @param string $public_pem The public RSA-PSS key in PEM format.
    * @param string $algorithm The hashing algorithm used for signing (e.g., 'SHA256').
    *
    * @throws CipherErrorException If there are issues with the public key or the verification process.
    * @throws InvalidArgumentException If the input data or key is invalid.
    *
    * @return bool True if the signature is valid, false otherwise.
    */
    public function verifyRsaPss(string $data, string $signature, string $public_pem, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $public_pem, $algorithm);
    }


    /**
    * Helper method to check if RSA payload size is acceptable.
    *
    * @param string $plaintext The plaintext to be encrypted.
    * @param int $lengthInBytes The length of the RSA key in bytes.
    * @param string|null $cipher Optional cipher to calculate padding.
    *
    * @return bool True if payload size is acceptable for RSA encryption, false otherwise.
    */
    protected function isRsaPayloadSizeAcceptable(string $plaintext, int $lengthInBytes, string $cipher = null): bool
    {
        // Adjust key length based on padding
        if (!is_null($cipher) && isset($this->padding[$cipher])) {
            $lengthInBytes -= $this->padding[$cipher];
        }

        // Prüfen, ob der Klartext zu groß ist
        return strlen($plaintext) <= $lengthInBytes;
    }

    /**
    * Validates the input data and output for encryption or decryption operations.
    *
    * This method checks whether the input data is not empty and ensures the output
    * variable is empty before processing. This is typically used to prevent overwriting
    * any existing data in the output variable and to ensure the input data is valid.
    *
    * @param string $data The input data to be encrypted or decrypted.
    * @param string $output The output variable that will store the result. Must be empty.
    *
    * @throws InvalidArgumentException If the input data is empty or the output is not empty.
    */
    private function validateInputOutputData(string $data, string $output): void
    {
        if (empty($data)) {
            throw new InvalidArgumentException(self::ERROR_EMPTY_DATA);
        }

        if (! empty($output)) {
            throw new InvalidArgumentException(self::ERROR_INVALID_OUTPUT);
        }
    }

    /**
    * Validates the cipher, passphrase, and initialization vector (IV) used in encryption or decryption.
    *
    * This method checks the validity of the cipher by ensuring it is one of the supported methods,
    * verifies that the passphrase has the correct length for the selected cipher, and checks
    * that the IV has the correct length based on the cipher being used.
    *
    * @param string $cipher The encryption algorithm identifier (e.g., 'aes-256-gcm').
    * @param string $passphrase The passphrase (key) used for encryption or decryption.
    * @param string $iv The initialization vector (IV) used for the selected cipher.
    *
    * @throws InvalidArgumentException If the cipher is not valid or supported, if the passphrase
    *                                  does not match the required length for the cipher, or if the IV
    *                                  length is incorrect for the selected cipher.
    */
    private function validateCipher(string $cipher, string $passphrase, string $iv): void
    {
        if (empty($cipher) || false == in_array($cipher, openssl_get_cipher_methods())) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_CIPHER, $cipher));
        }

        if (openssl_cipher_iv_length($cipher) > 0 && empty($passphrase) || strlen($passphrase) !== openssl_cipher_key_length($cipher)) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_PASSPHRASE, openssl_cipher_key_length($cipher), strlen($passphrase)));
        }

        if (empty($iv) || strlen($iv) !== openssl_cipher_iv_length($cipher)) {
            throw new InvalidArgumentException(sprintf(self::ERROR_INVALID_IV, openssl_cipher_iv_length($cipher), strlen($iv)));
        }
    }
}
