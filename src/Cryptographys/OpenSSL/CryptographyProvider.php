<?php

namespace Phithi92\JsonWebToken\Cryptographys\OpenSSL;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidAsymetricKeyException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidInitializeVectorException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidSecretLengthException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidAsymetricKeyLength;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnexpectedOutputException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\EmptyFieldException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Cryptographys\OpenSSL\AlgorithmsTrait;
use Phithi92\JsonWebToken\Cryptographys\Provider;

use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_private_decrypt;
use function openssl_pkey_get_details;
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
final class CryptographyProvider extends Provider
{
    use AlgorithmsTrait;

    private array $digestAlgorithms = [];
    private array $cipherAlgorithms = [];

    /**
     * Retrieves the list of supported digest algorithms.
     *
     * If the list of digest algorithms is not already set, this method
     * populates it using OpenSSL's available message digest methods.
     *
     * @return array An array of supported digest algorithm names.
     */
    public function getDigestAlgorithms(): array
    {
        if (empty($this->digestAlgorithms)) {
            $this->digestAlgorithms = openssl_get_md_methods();
        }
        return $this->digestAlgorithms;
    }

    /**
     * Retrieves the list of supported cipher algorithms.
     *
     * If the list of cipher algorithms is not already set, this method
     * populates it using OpenSSL's available cipher methods.
     *
     * @return array An array of supported cipher algorithm names.
     */
    public function getCipherAlgorithms(): array
    {
        if (empty($this->cipherAlgorithms)) {
            $this->cipherAlgorithms = openssl_get_cipher_methods();
        }
        return $this->cipherAlgorithms;
    }

    /**
     * Generates a random byte string of the specified length.
     *
     * This method uses OpenSSL to create a pseudorandom byte string, which
     * can be used for cryptographic purposes.
     *
     * @param  int $length The length of the random byte string to generate.
     * @return string A pseudorandom byte string of the specified length.
     */
    public function randomBytes(int $length): string
    {
        return openssl_random_pseudo_bytes($length);
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
     * @throws DecryptionException if decryption fails.
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
        $decrypted = openssl_decrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            throw new DecryptionException();
        }

        if (empty($decrypted)) {
            throw new DecryptionException();
        }

        $decrypted_data = $decrypted;
    }

    /**
     * Encrypts data using a passphrase and AES cipher.
     *
     * @param string $data         The data to be encrypted.
     * @param string &$encrypted_data Reference to the output of encrypted data.
     * @param string $cipher       The encryption algorithm (e.g., AES-256-CBC).
     * @param string $passphrase   The secret key used for encryption.
     * @param string $iv           The initialization vector used in encryption.
     * @param string &$tag         Reference to the authentication tag generated
     *                             for integrity.
     *
     * @throws EncryptionException if encryption fails.
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
        $encrypted = openssl_encrypt($data, $cipher, $passphrase, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted === false) {
            throw new EncryptionException();
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted)) {
            throw new EncryptionException();
        }

        $encrypted_data = $encrypted;
    }

    /**
     * Decrypts data using a private RSA key.
     *
     * @param string $data            The encrypted data to be decrypted.
     * @param int    $padding         The padding algorithm used during encryption.
     *
     * @return string                 The decrypted plaintext data.
     *
     * @throws EmptyFieldException    If the input data is empty.
     * @throws DecryptionException    If decryption fails or results in empty output.
     */
    public function rsaDecryptWithPrivateKey(string $data, int $padding): string
    {
        if (empty($data)) {
            throw new EmptyFieldException('data');
        }

        // Retrieve the private key from PEM string
        $private_key = $this->getPrivateKey();

        // Initialize decrypted data variable
        $decrypted_data = '';

        // Decrypt data with RSA private key
        if (!openssl_private_decrypt($data, $decrypted_data, $private_key, $padding)) {
            throw new DecryptionException();
        }

        // Result may be empty if decryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($decrypted_data)) {
            throw new DecryptionException();
        }

        return $decrypted_data;
    }

    /**
     * Encrypts data using a public RSA key.
     *
     * @param string $data            The data to be encrypted.
     * @param int    $padding         The padding algorithm used during encryption.
     *
     * @return string                 The encrypted data in binary format.
     *
     * @throws EmptyFieldException    If the input data is empty.
     * @throws EncryptionException    If encryption fails or results in empty output.
     */
    public function rsaEncryptWithPublicKey(string $data, int $padding): string
    {
        if (empty($data)) {
            throw new EmptyFieldException('data');
        }

        $encrypted_data = '';

        // Encrypt data with RSA public key
        if (!openssl_public_encrypt($data, $encrypted_data, $this->getPublicKey(), $padding)) {
            throw new EncryptionException();
        }

        // Result may be empty if encryption libary is configured incorrectly
        // or if memory allocation fails
        if (empty($encrypted_data)) {
            throw new EncryptionException();
        }

        return $encrypted_data;
    }

    public function aesKeyWrapEncrypt(string $cek, int $length)
    {
        $algo = "aes-$length-ecb";

        // Initialisierungsvektor für AES Key Wrap
        $iv = hex2bin('A6A6A6A6A6A6A6A6');
        if ($iv === false) {
            throw new \Exception('Invalid IV initialization.');
        }
        $ciphertext = $iv;

        // CEK in 8-Byte-Blöcke unterteilen
        $n = strlen($cek) / 8;
        $blocks = str_split($cek, 8);

        // Anzahl der Runden berechnen
        $rounds = 6 * $n;

        for ($j = 0; $j < $rounds; $j++) {
            $blockIndex = $j % $n;

            if (!isset($blocks[$blockIndex])) {
                throw new \Exception('Invalid block index.');
            }

            // Pack the round number
            /** @var string $packed */
            $packed = pack('N', $j + 1);

            // XOR-Operation: Garantieren, dass beide Operanden Strings sind
            /** @var string $xorOperand */
            $xorOperand = $packed . $blocks[$blockIndex];

            /** @var string $ciphertext */
            if (strlen($xorOperand) !== strlen($ciphertext)) {
                throw new \Exception(
                    'XOR operands must have the same length. ' .
                    'Ciphertext length: ' . strlen($ciphertext) . ', XOR operand length: ' . strlen($xorOperand)
                );
            }

            // Perform XOR
            $block = $ciphertext ^ $xorOperand;

            $encrypted = openssl_encrypt(
                $block,
                $algo,
                $this->getPassphrase(),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
            );

            if ($encrypted === false) {
                throw new \Exception('Encryption failed.');
            }

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
            throw new DecryptionException();
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
     * @throws EncryptionException If the encryption process fails.
     */
    public function pbes2EncryptKey(
        string $password,
        string $key,
        string|null $salt = null,
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
            throw new EncryptionException();
        }

        // Concatenate salt, IV, and the encrypted key, and encode them in base64
        return base64_encode($salt . $iv . $encryptedKey);
    }

    /**
     * Encrypts a message using AES in GCM mode.
     *
     * @param  string $plaintext The plaintext message to be encrypted
     * @param  int    $bitLength The length of the key (128, 192, or 256 bits)
     * @param  string $iv        The initialization vector (IV)
     * @param  string $authTag   The authentication tag (generated by the function)
     * @param  int    $tagLength The length of the authentication tag (default is 16 bytes)
     * @return string The encrypted ciphertext
     * @throws EncryptionException On encryption failure
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
            throw new EncryptionException();
        }

        return $ciphertext;
    }

    /**
     * Decrypts a message using AES in GCM mode.
     *
     * @param  string $ciphertext The encrypted message (ciphertext)
     * @param  int    $bitLength  The length of the key (128, 192, or 256 bits)
     * @param  string $iv         The initialization vector (IV)
     * @param  string $authTag    The authentication tag (to verify integrity)
     * @return string The decrypted plaintext
     * @throws DecryptionException If decryption fails or the authentication tag is invalid
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
            throw new DecryptionException();
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
     * Signs data using the specified algorithm and private RSA key.
     *
     * @param string $data            The data to be signed.
     * @param string &$signature      The variable to store the generated signature.
     * @param string $algorithm       The signing algorithm to use (e.g., SHA256, SHA512).
     *
     * @return void                   The signature is returned by reference in the $signature variable.
     *
     * @throws EmptyFieldException          If the input data or signature variable is invalid.
     * @throws InvalidAsymetricKeyException If the private key is invalid or its details cannot be retrieved.
     * @throws InvalidAsymetricKeyLength    If the private key length is greater than the expected length for
     *                                      the algorithm.
     * @throws EncryptionException          If signing the data fails.
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
            throw new InvalidAsymetricKeyException();
        }

        [$type, $length] = $this->extractAlgorithmComponents($algorithm);

        // Validate key length
        $key_length = $key_details['bits'] / 8;
        if ($key_length > $length) {
            throw new InvalidAsymetricKeyLength($key_length, $length);
        }

        // Directly sign the data using the private key and algorithm
        if (!openssl_sign($data, $signature, $private_key, $algorithm)) {
            throw new EncryptionException();
        }
    }

    /**
     * Signs data using RSA-PSS with the same logic as RSA.
     *
     * @param string $data        The data to be signed.
     * @param string &$signature  The variable to store the generated signature.
     * @param string $algorithm   The signing algorithm to be used.
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
     * @param string $algorithm  The algorithm used for signing (e.g., 'SHA256', 'RSA-PSS').
     *
     * @return bool True if the signature is valid, false otherwise.
     */
    public function verifyWithAlgorithm(string $data, string $signature, string $algorithm): bool
    {
        if (empty($data)) {
            throw new EmptyFieldException('data');
        }

        if (empty($signature)) {
            throw new EmptyFieldException('signature');
        }

        if (!$this->isSupportedDigestAlgorithm($algorithm)) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        // Verify the signature using the public key and algorithm
        $verification_result = openssl_verify($data, $signature, $this->getPublicKey(), $algorithm);

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
     * @param string $algorithm  The hashing algorithm used for signing (e.g., 'SHA256').
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
     * @param string $algorithm  The hashing algorithm used for signing (e.g., 'SHA256').
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
    protected function isRsaPayloadSizeAcceptable(
        string $plaintext,
        int $lengthInBytes,
        string|null $cipher = null
    ): bool {
        // Adjust key length based on padding
        if (!is_null($cipher) && isset($this->paddingLength[$cipher])) {
            $lengthInBytes -= $this->paddingLength[$cipher];
        }

        // Prüfen, ob der Klartext zu groß ist
        return strlen($plaintext) <= $lengthInBytes;
    }

    /**
     * Checks if the given algorithm is a supported digest algorithm.
     *
     * This method compares the provided algorithm against the list of
     * supported digest algorithms and returns whether it is supported.
     *
     * @param  string $algorithm The digest algorithm to check.
     * @return bool Returns `true` if the algorithm is supported, otherwise `false`.
     */
    private function isSupportedDigestAlgorithm(string $algorithm): bool
    {
        return in_array($algorithm, $this->getDigestAlgorithms());
    }

    /**
     * Checks if the given algorithm is a supported cipher algorithm.
     *
     * This method compares the provided algorithm against the list of
     * supported cipher algorithms and returns whether it is supported.
     *
     * @param  mixed $algorithm The cipher algorithm to check.
     * @return bool Returns `true` if the algorithm is supported, otherwise `false`.
     */
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
     */
    private function validateInputOutputData(string $data, string $output): void
    {
        if (empty($data)) {
            throw new EmptyFieldException('data');
        }

        if (! empty($output)) {
            throw new UnexpectedOutputException();
        }
    }

    /**
     * Validates the specified cipher, passphrase, and initialization vector (IV) for encryption or decryption.
     *
     * This method ensures the following:
     * - The cipher algorithm is supported and recognized.
     * - The passphrase (key) meets the length requirements for the chosen cipher.
     * - The initialization vector (IV) has the correct length as required by the cipher.
     *
     * @param string $cipher     The identifier of the encryption algorithm (e.g., 'aes-256-gcm').
     * @param string $passphrase The encryption or decryption passphrase (key).
     * @param string $iv         The initialization vector (IV) specific to the selected cipher.
     *
     * @throws UnsupportedAlgorithmException If the cipher algorithm is not supported.
     * @throws InvalidSecretLengthException           If the passphrase length is invalid for the specified cipher.
     * @throws InvalidInitializeVectorException If the IV length is incorrect for the specified cipher.
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
            throw new InvalidSecretLengthException(
                strlen($passphrase),
                openssl_cipher_key_length($cipher)
            );
        }

        if (empty($iv) || strlen($iv) !== openssl_cipher_iv_length($cipher)) {
            throw new InvalidInitializeVectorException(
                strlen($passphrase),
                openssl_cipher_iv_length($cipher)
            );
        }
    }

    /**
     * Extracts the algorithm type and bit length from a given algorithm string.
     * Example: 'sha256' -> ['sha', 256].
     *
     * @param  string $algorithm The algorithm string (e.g., 'sha256').
     * @return array An array containing the algorithm type and bit length.
     * @throws UnsupportedAlgorithmException If the algorithm string is not supported.
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
}
