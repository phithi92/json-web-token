<?php

namespace Phithi92\JsonWebToken\Cryptography\OpenSSL;

use Phithi92\JsonWebToken\Exception\InvalidArgument;
use Phithi92\JsonWebToken\Exception\OpensslError;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Cryptography\OpenSSL\AlgorithmRegistry;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
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
final class CryptoManager extends AlgorithmRegistry
{
    // Error messages for various encryption and decryption failure scenarios
    private const ERROR_INVALID_PRIVATE_KEY_DETAILS = 'Error. Cant read private key propertys';
    private const ERROR_INVALID_IV = 'Invalid IV length %s bytes but %s bytes expexted.';
    private const ERROR_INVALID_KEY_LENGTH = 'Invalid key length %s bytes but %s bytes expexted.';
    private const ERROR_INVALID_PASSPHRASE = 'Invalid Passphrase. Expect %s bytes but %s bytes given.';
    private const ERROR_INVALID_OUTPUT = 'Output variable need to be empty';
    private const ERROR_EMPTY_DATA = 'The data cannot be empty.';

    private ?OpenSSLAsymmetricKey $publicKey = null;
    private ?OpenSSLAsymmetricKey $privateKey = null;
    private string $passphrase = '';

    private ?array $digestAlgorithms = null;
    private ?array $cipherAlgorithms = null;

    public function __construct(JwtAlgorithmManager $manager)
    {

        if (empty($manager->getPassphrase())) {
            $this->setPrivateKey($manager->getPrivateKey());
            $this->setPublicKey($manager->getPublicKey());
        } else {
            $this->setPassphrase($manager->getPassphrase());
        }
    }

    // Destructor ensures that the keys are explicitly deleted
    public function __destruct()
    {
        if ($this->privateKey !== null) {
            $this->privateKey = null;
        }

        if ($this->publicKey !== null) {
            $this->publicKey = null;
        }
    }

    public function getDigestAlgorithms(): array
    {
        if ($this->digestAlgorithms === null) {
            $this->digestAlgorithms = openssl_get_md_methods();
        }

        return $this->digestAlgorithms;
    }


    public function getCipherAlgorithms(): array
    {
        if ($this->cipherAlgorithms === null) {
            $this->cipherAlgorithms = openssl_get_cipher_methods();
        }

        return $this->cipherAlgorithms;
    }

    public function randomBytes(int $length): string
    {
        return openssl_random_pseudo_bytes($length);
    }

    /**
     * Sets the public key.
     *
     * @param  string $key The public key in string format.
     * @return self
     * @throws InvalidArgument if the provided key is invalid.
     */
    public function setPublicKey(OpenSSLAsymmetricKey $key): self
    {
        // Store the public key in the class property
        $this->publicKey = $key;

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
     * @param  string $key The private key in string format.
     * @return self
     * @throws InvalidArgument if the provided key is invalid.
     */
    public function setPrivateKey(OpenSSLAsymmetricKey $key): self
    {
        // Store the private key in the class property
        $this->privateKey = $key;

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

    private function setPassphrase(string $passphrase): self
    {
        $this->passphrase = $passphrase;

        return $this;
    }

    private function getPassphrase(): string
    {
        return $this->passphrase;
    }


    /**
     * Decrypts data using a passphrase and AES cipher.
     *
     * @param string      $data            The encrypted data to be decrypted.
     * @param string      &$decrypted_data Reference to the output of decrypted data.
     * @param string      $cipher          The encryption algorithm (e.g., AES-256-CBC).
     * @param string      $passphrase      The secret key used for decryption.
     * @param string      $iv              The initialization vector used in encryption.
     * @param string|null $tag             (Optional) The authentication tag for verifying integrity.
     *
     * @throws InvalidArgument if IV length is incorrect.
     * @throws OpensslError if decryption fails.
     */
    public function decryptWithPassphrase(
        string $data,
        string &$decrypted_data,
        string $cipher,
        string $passphrase,
        string $iv,
        ?string $tag = null
    ): void {
        $this->validateInputOutputData($data, $decrypted_data);

        $this->validateCipher($cipher, $passphrase, $iv);

        // Decrypt data with AES and optional tag for integrity checking
        $decrypted_data = openssl_decrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted_data === false) {
            throw OpensslError::cipherDecryptionFailed($cipher);
        }

        if (empty($decrypted_data)) {
            throw OpensslError::cipherEmptyResult($cipher);
        }
    }

    /**
     * Encrypts data using a passphrase and AES cipher.
     *
     * @param string $data         The data to be encrypted.
     * @param string &$cipher_data Reference to the output of encrypted data.
     * @param string $cipher       The encryption algorithm (e.g., AES-256-CBC).
     * @param string $passphrase   The secret key used for encryption.
     * @param string $iv           The initialization vector used in encryption.
     * @param string &$tag         Reference to the authentication tag generated
     *                             for integrity.
     *
     * @throws InvalidArgument if any argument is empty.
     * @throws OpensslError if encryption fails.
     */
    public function encryptWithPassphrase(
        string $data,
        string &$encrypted_data,
        string $cipher,
        string $passphrase,
        string $iv,
        string &$tag
    ): void {
        // Validate input parameters
        $this->validateInputOutputData($data, $encrypted_data);

        $this->validateCipher($cipher, $passphrase, $iv);

        // Encrypt data with AES and generate an authentication tag
        $encrypted_data = openssl_encrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted_data === false) {
            throw OpensslError::cipherEncryptionFailed($cipher);
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted_data)) {
            throw OpensslError::cipherEmptyResult($cipher);
        }
    }

    /**
     * Decrypts data using a private RSA key.
     *
     * @param string $data            The encrypted data to be decrypted.
     * @param string &$decrypted_data Reference to the output of decrypted data.
     * @param string $private_pem     The private key in PEM format.
     * @param int    $padding         The padding algorithm used during encryption.
     *
     * @throws InvalidArgument if the private key is invalid.
     * @throws OpensslError if decryption fails.
     */
    public function rsaDecryptWithPrivateKey(string $data, int $padding): string
    {
        if (empty($data)) {
            throw new InvalidArgument(self::ERROR_EMPTY_DATA);
        }

        // Retrieve the private key from PEM string
        $private_key = $this->getPrivateKey();

        // Initialize decrypted data variable
        $decrypted_data = '';

        // Decrypt data with RSA private key
        if (!openssl_private_decrypt($data, $decrypted_data, $private_key, $padding)) {
            throw OpensslError::opensslPrivateKeyDecryptFailed(openssl_error_string());
        }

        // Result may be empty if decryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($decrypted_data)) {
            throw OpensslError::opensslEmptyResult(openssl_error_string());
        }

        return $decrypted_data;
    }

    /**
     * Encrypts data using a public RSA key.
     *
     * @param string $data            The data to be encrypted.
     * @param string &$encrypted_data Reference to the output of encrypted data.
     * @param string $public_pem      The public key in PEM format.
     * @param int    $padding         The padding algorithm used during encryption.
     *
     * @throws InvalidArgument if the public key is invalid.
     * @throws OpensslError if encryption fails.
     */
    public function rsaEncryptWithPublicKey(string $data, int $padding): string
    {
        if (empty($data)) {
            throw new InvalidArgument(self::ERROR_EMPTY_DATA);
        }

        $encrypted_data = '';

        // Encrypt data with RSA public key
        if (!openssl_public_encrypt($data, $encrypted_data, $this->getPublicKey(), $padding)) {
            throw OpensslError::opensslPublicKeyEncryptFailed(openssl_error_string());
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted_data)) {
            throw OpensslError::opensslEmptyResult(openssl_error_string());
        }

        return $encrypted_data;
    }

    public function aesKeyWrapEncrypt(string $cek, int $length)
    {
        $algo = "aes-$length-ecb";

        // Initialisierungsvektor für AES Key Wrap
        $iv = hex2bin('A6A6A6A6A6A6A6A6');
        $ciphertext = $iv;

        // CEK in 8-Byte-Blöcke unterteilen
        $n = strlen($cek) / 8;
        $blocks = str_split($cek, 8);

        // Anzahl der Runden berechnen
        $rounds = 6 * $n;

        for ($j = 0; $j < $rounds; $j++) {
            $blockIndex = $j % $n;

            // Block erzeugen und verschlüsseln
            $block = $ciphertext ^ pack('N', $j + 1) . $blocks[$blockIndex];
            $encrypted = openssl_encrypt(
                $block,
                $algo,
                $this->getPassphrase(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
            );

            // 8-Byte IV extrahieren und Block aktualisieren
            $ciphertext = substr($encrypted, 0, 8);
            $blocks[$blockIndex] = substr($encrypted, 8);
        }

        // Endgültiges Ergebnis: Initialisierungsvektor + verschlüsselte Blöcke
        return $ciphertext . implode('', $blocks);
    }

    public function aesKeyWrapDecrypt($ciphertextKey)
    {
        // Define the IV and integrity check value
        $iv = hex2bin('A6A6A6A6A6A6A6A6'); // Standard IV for AES Key Wrap

        // Split the ciphertext into the initial IV and blocks
        $ciphertextIV = substr($ciphertextKey, 0, 8);
        $blocks = str_split(substr($ciphertextKey, 8), 8); // 8-Byte-Blöcke erstellen
        $n = count($blocks);

        // Calculate the number of rounds
        $rounds = 6 * $n;

        // Perform the reverse rounds
        for ($j = $rounds; $j > 0; $j--) {
            $blockIndex = ($j - 1) % $n;

            // Build the block to decrypt
            $block = $ciphertextIV . $blocks[$blockIndex];

            // Apply AES decryption in ECB mode
            $decrypted = openssl_decrypt(
                $block,
                'aes-128-ecb',
                $this->getPassphrase(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
            );

            // Split the decrypted data into the IV and block
            $ciphertextIV = substr($decrypted, 0, 8) ^ pack('N', $j);
            $blocks[$blockIndex] = substr($decrypted, 8);
        }

        // Verify that the IV matches the original IV
        if ($ciphertextIV !== $iv) {
            throw new Exception("Decryption failed: Integrity check failed.");
        }

        // Rebuild the plaintext key from the blocks
        return implode('', $blocks);
    }

    /**
     * Performs ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral-Static) key agreement.
     *
     * @param  string $algo The hashing algorithm to use for key derivation, defaults to 'sha256'.
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
     * @param  string      $password   The password to derive the encryption key.
     * @param  string      $key        The key to be encrypted.
     * @param  string|null $salt       Optional salt for the key derivation, if not provided, a random
     *                                 salt will be generated.
     * @param  int         $iterations Number of iterations for the PBKDF2 function, defaults to 10000.
     * @param  string      $algorithm  The encryption algorithm to use, defaults to 'aes-256-cbc'.
     * @return string The encrypted key, base64-encoded, along with the salt and IV.
     * @throws Exception If the encryption process fails.
     */
    public function pbes2EncryptKey(
        string $password,
        string $key,
        string $salt = null,
        int $iterations = 10000,
        string $algorithm = 'aes-256-cbc'
    ): string {
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
            throw OpensslError::opensslEncryptFailed($algorithm);
        }

        // Concatenate salt, IV, and the encrypted key, and encode them in base64
        return base64_encode($salt . $iv . $encryptedKey);
    }

    /**
     * Encrypts a message using AES in GCM mode.
     *
     * @param  string $plaintext The plaintext message to be encrypted
     * @param  string $key       The symmetric encryption key
     * @param  int    $bitLength The length of the key (128, 192, or 256 bits)
     * @param  string $iv        The initialization vector (IV)
     * @param  string $authTag   The authentication tag (generated by the function)
     * @param  int    $tagLength The length of the authentication tag (default is 16 bytes)
     * @return string The encrypted ciphertext
     * @throws Exception On encryption failure
     */
    public function aesGcmEncrypt(
        string $plaintext,
        int $bitLength,
        string $iv,
        string &$authTag,
        int $tagLength = 16
    ): string {

        // Determine the cipher algorithm based on key length (e.g., aes-128-gcm, aes-256-gcm)
        $cipherAlgo = 'aes-' . $bitLength . '-gcm';

        // Encrypt the message in GCM mode
        $ciphertext = openssl_encrypt(
            $plaintext,        // The plaintext message
            $cipherAlgo,       // The AES-GCM cipher algorithm
            $this->getPassphrase(), // The encryption key
            OPENSSL_RAW_DATA,  // Use raw binary data for output
            $iv,               // The initialization vector (IV)
            $authTag,          // The authentication tag (generated by the function)
            '',                // Additional authenticated data (optional, empty in this case)
            $tagLength         // The length of the authentication tag (default 16 bytes)
        );

        // Error handling
        if ($ciphertext === false) {
            throw OpensslError::opensslEncryptFailed($cipherAlgo, openssl_error_string());
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message using AES in GCM mode.
     *
     * @param  string $ciphertext The encrypted message (ciphertext)
     * @param  string $key        The symmetric key used for decryption
     * @param  int    $bitLength  The length of the key (128, 192, or 256 bits)
     * @param  string $iv         The initialization vector (IV)
     * @param  string $authTag    The authentication tag (to verify integrity)
     * @return string The decrypted plaintext
     * @throws Exception If decryption fails or the authentication tag is invalid
     */
    public function aesGcmDecrypt(string $ciphertext, int $bitLength, string $iv, string $authTag): string
    {
        // Determine the cipher algorithm based on the key length (e.g., aes-128-gcm, aes-256-gcm)
        $cipherAlgo = 'aes-' . $bitLength . '-gcm';

        // Perform AES-GCM decryption
        $plaintext = openssl_decrypt(
            $ciphertext,        // The ciphertext to decrypt
            $cipherAlgo,        // The AES-GCM algorithm
            $this->getPassphrase(),  // The symmetric decryption key
            OPENSSL_RAW_DATA,   // Use raw data output
            $iv,                // The initialization vector (IV)
            $authTag            // The authentication tag
        );

        // Check for errors
        if ($plaintext === false) {
            throw OpensslError::cipherEmptyResult(openssl_error_string() . ' ' . $cipherAlgo);
        }

        return $plaintext;
    }

    public function encryptWithEcdhEsP521($payload, $recipientPublicKey)
    {
        // Erstelle ein temporäres Schlüsselpaar (Ephemeral Key)
        $ephemeralKey = openssl_pkey_new(['curve_name' => 'P-521', 'private_key_type' => OPENSSL_KEYTYPE_EC]);

        // Extrahiere den öffentlichen Schlüssel
        $ephemeralDetails = openssl_pkey_get_details($ephemeralKey);
        $ephemeralPublicKey = $ephemeralDetails['key'];

        // Berechne das geteilte Geheimnis zwischen dem temporären privaten und dem Empfängeröffentlichen Schlüssel
        openssl_pkey_export($ephemeralKey, $ephemeralPrivateKey);
        $sharedSecret = openssl_dh_compute_key($recipientPublicKey, $ephemeralKey);

        // Der sharedSecret kann jetzt mit einem symmetrischen Verschlüsselungsalgorithmus
        // verwendet werden (z.B. AES-GCM)
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

    public function decryptWithEcdhEsP521($ciphertext, $iv, $tag, $ephemeralPublicKey, $recipientPrivateKey)
    {
        // Berechne das geteilte Geheimnis zwischen dem Empfängerprivaten und dem Ephemeral-öffentlichen Schlüssel
        $sharedSecret = openssl_dh_compute_key($ephemeralPublicKey, $recipientPrivateKey);

        // Symmetrischen Schlüssel generieren
        $key = hash('sha256', $sharedSecret, true);

        // Entschlüsseln mit AES-GCM
        $plaintext = openssl_decrypt(
            base64_decode($ciphertext),
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            base64_decode($iv),
            base64_decode($tag)
        );

        return $plaintext;
    }

    /**
     * Generic method to sign data using a private key.
     *
     * This method signs the given data using the specified algorithm and private key.
     * It validates the private key, checks the key length, and applies optional padding (such as RSA-PSS)
     * before performing the signing operation.
     *
     * @param string   $data        The data to be signed.
     * @param string   &$signature  The variable to store the generated signature.
     * @param string   $algorithm   The algorithm to use for signing (e.g., 'SHA256', 'RSA-PSS').
     * @param string   $private_pem The private key in PEM format.
     * @param int|null $padding     Optional padding parameter for algorithms like RSA-PSS.
     *
     * @throws OpensslError If there are issues with the private key or the signing process.
     * @throws InvalidArgument If the key length is invalid.
     */
    public function signWithAlgorithm(
        string $data,
        string &$signature,
        string $algorithm
    ): void {
        $this->validateInputOutputData($data, $signature);

        // Retrieve and validate private key
        $private_key = $this->getPrivateKey();

        // Get key details
        $key_details = openssl_pkey_get_details($private_key);
        if (!$key_details || !isset($key_details['bits'])) {
            throw new InvalidArgument(self::ERROR_INVALID_PRIVATE_KEY_DETAILS);
        }

        [$type, $length] = $this->extractAlgorithmComponents($algorithm);

        // Validate key length
        $key_length = $key_details['bits'] / 8;
        if ($key_length > $length) {
            throw new InvalidArgument(sprintf(self::ERROR_INVALID_KEY_LENGTH, $key_length, $length));
        }

        // Directly sign the data using the private key and algorithm
        if (!openssl_sign($data, $signature, $private_key, $algorithm)) {
            throw OpensslError::signatureCreationfailed($algorithm);
        }
    }

    /**
     * Signs data using RSA-PSS with the same logic as RSA.
     *
     * @param string $data        The data to be signed.
     * @param string &$signature  The variable to store the generated signature.
     * @param string $algorithm   The signing algorithm to be used.
     * @param string $private_pem The private RSA key in PEM format.
     *
     * @see signWithAlgorithm
     */
    public function signRsa(string $data, string &$signature, string $algorithm): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm);
    }

    /**
     * Signs data using RSA-PSS with the same logic as RSA.
     *
     * @param string $data        The data to be signed.
     * @param string &$signature  The variable to store the generated signature.
     * @param string $algorithm   The signing algorithm to be used.
     * @param string $private_pem The private RSA key in PEM format.
     *
     * @see signWithAlgorithm
     */
    public function signRsaPss(string $data, string &$signature, string $algorithm): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm);
    }

    /**
     * Signs data using ECDSA with the same logic as RSA.
     *
     * @param string $data        The data to be signed.
     * @param string &$signature  The variable to store the generated signature.
     * @param string $algorithm   The signing algorithm to be used.
     * @param string $private_pem The private ECDSA key in PEM format.
     *
     * @see signWithAlgorithm
     */
    public function signEcdsa(string $data, string &$signature, string $algorithm): void
    {
        $this->signWithAlgorithm($data, $signature, $algorithm);
    }

    /**
     * Generic method to verify a signature using a public key.
     *
     * This method verifies the signature for the given data using the specified public key and algorithm.
     *
     * @param string $data       The original data that was signed.
     * @param string $signature  The signature that needs to be verified.
     * @param string $public_pem The public key in PEM format.
     * @param string $algorithm  The algorithm used for signing (e.g., 'SHA256', 'RSA-PSS').
     *
     * @throws OpensslError If there are issues with the public key or the verification process.
     * @throws InvalidArgument If the input data or key is invalid.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyWithAlgorithm(string $data, string $signature, string $algorithm): bool
    {
        // Validate inputs (data and signature should not be empty)
        if (empty($data) || empty($signature)) {
            throw new InvalidArgument(self::ERROR_EMPTY_DATA);
        }

        if (!$this->isSupportedDigestAlgorithm($algorithm)) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        // Verify the signature using the public key and algorithm
        $verification_result = openssl_verify($data, $signature, $this->getPublicKey(), $algorithm);

        if (false === is_int($verification_result)) {
            throw new InvalidArgument(openssl_error_string());
        }

        // Return true if the signature is valid, otherwise false
        return (bool) $verification_result;
    }

    /**
     * Verifies an RSA signature using a public key.
     *
     * This method verifies the signature for the given data using RSA and the specified public key.
     *
     * @param string $data      The original data that was signed.
     * @param string $signature The signature that needs to be verified.
     * @param string $algorithm The hashing algorithm used for signing (e.g., 'SHA256').
     *
     * @throws OpensslError If there are issues with the public key or the verification process.
     * @throws InvalidArgument If the input data or key is invalid.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyRsa(string $data, string $signature, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $algorithm);
    }

    /**
     * Verifies an ECDSA signature using a public key.
     *
     * This method verifies the signature for the given data using ECDSA and the specified public key.
     *
     * @param string $data       The original data that was signed.
     * @param string $signature  The signature that needs to be verified.
     * @param string $public_pem The public ECDSA key in PEM format.
     * @param string $algorithm  The hashing algorithm used for signing (e.g., 'SHA256').
     *
     * @throws OpensslError If there are issues with the public key or the verification process.
     * @throws InvalidArgument If the input data or key is invalid.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyEcdsa(string $data, string $signature, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $algorithm);
    }

    /**
     * Verifies an RSA-PSS signature using a public key.
     *
     * This method verifies the signature for the given data using RSA-PSS and the specified public key.
     *
     * @param string $data       The original data that was signed.
     * @param string $signature  The signature that needs to be verified.
     * @param string $public_pem The public RSA-PSS key in PEM format.
     * @param string $algorithm  The hashing algorithm used for signing (e.g., 'SHA256').
     *
     * @throws OpensslError If there are issues with the public key or the verification process.
     * @throws InvalidArgument If the input data or key is invalid.
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyRsaPss(string $data, string $signature, string $algorithm): bool
    {
        return $this->verifyWithAlgorithm($data, $signature, $algorithm);
    }


    /**
     * Helper method to check if RSA payload size is acceptable.
     *
     * @param string      $plaintext     The plaintext to be encrypted.
     * @param int         $lengthInBytes The length of the RSA key in bytes.
     * @param string|null $cipher        Optional cipher to calculate padding.
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

    private function isSupportedDigestAlgorithm(string $algorithm): bool
    {
        return in_array($algorithm, $this->getDigestAlgorithms());
    }

    private function isSupportedCipherAlgorithm($algorithm): bool
    {
        return in_array($algorithm, $this->getCipherAlgorithms());
    }

    /**
     * Validates the input data and output for encryption or decryption operations.
     *
     * This method checks whether the input data is not empty and ensures the output
     * variable is empty before processing. This is typically used to prevent overwriting
     * any existing data in the output variable and to ensure the input data is valid.
     *
     * @param string $data   The input data to be encrypted or decrypted.
     * @param string $output The output variable that will store the result. Must be empty.
     *
     * @throws InvalidArgument If the input data is empty or the output is not empty.
     */
    private function validateInputOutputData(string $data, string $output): void
    {
        if (empty($data)) {
            throw new InvalidArgument(self::ERROR_EMPTY_DATA);
        }

        if (! empty($output)) {
            throw new InvalidArgument(self::ERROR_INVALID_OUTPUT);
        }
    }

    /**
     * Validates the cipher, passphrase, and initialization vector (IV) used in encryption or decryption.
     *
     * This method checks the validity of the cipher by ensuring it is one of the supported methods,
     * verifies that the passphrase has the correct length for the selected cipher, and checks
     * that the IV has the correct length based on the cipher being used.
     *
     * @param string $cipher     The encryption algorithm identifier (e.g., 'aes-256-gcm').
     * @param string $passphrase The passphrase (key) used for encryption or decryption.
     * @param string $iv         The initialization vector (IV) used for the selected cipher.
     *
     * @throws InvalidArgument If the cipher is not valid or supported, if the passphrase
     *                                  does not match the required length for the cipher, or if the IV
     *                                  length is incorrect for the selected cipher.
     */
    private function validateCipher(string $cipher, string $passphrase, string $iv): void
    {
        if (! $this->isSupportedCipherAlgorithm($cipher)) {
            throw new UnsupportedAlgorithmException($cipher);
        }

        if (
            openssl_cipher_iv_length($cipher) > 0 && empty($passphrase)
            || strlen($passphrase) !== openssl_cipher_key_length($cipher)
        ) {
            throw new InvalidArgument(
                sprintf(
                    self::ERROR_INVALID_PASSPHRASE,
                    openssl_cipher_key_length($cipher),
                    strlen($passphrase)
                )
            );
        }

        if (empty($iv) || strlen($iv) !== openssl_cipher_iv_length($cipher)) {
            throw new InvalidArgument(
                sprintf(
                    self::ERROR_INVALID_IV,
                    openssl_cipher_iv_length($cipher),
                    strlen($iv)
                )
            );
        }
    }

    /**
     * Extracts the algorithm type and bit length from a given algorithm string.
     * Example: 'sha256' -> ['sha', 256].
     *
     * @param  string $algorithm The algorithm string (e.g., 'sha256').
     * @return array An array containing the algorithm type and bit length.
     * @throws \InvalidArgumentException If the algorithm string is not supported.
     */
    public function extractAlgorithmComponents(string $algorithm): array
    {
        if (!preg_match('/^(sha)(256|384|512)$/', $algorithm, $matches)) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        $algorithmType = $matches[1];
        $hashLength = (int) $matches[2];

        return [$algorithmType, $hashLength];
    }

    /**
     * Retrieves the key length in bits for a given algorithm.
     *
     * @param  int $algorithm The algorithm constant (e.g., OPENSSL_ALGO_SHA256).
     * @return int The key length in bits, or 0 if the algorithm is not mapped.
     */
    public function getKeyLength(int $algorithm): int
    {
        return $this->key_length[$algorithm] ?? 0;
    }
}
