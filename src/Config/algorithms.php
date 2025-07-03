<?php

return [

    // HMAC Signatures
    'HS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS256',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha256',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ]
    ],

    'HS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS384',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha384',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ]
    ],

    'HS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ]
    ],

    // RSA Signatures
    'RS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS256',
        'signing_algorithm' => [
            'name' => 'RS256',
            'hash_algorithm' => 'sha256',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ]
    ],

    'RS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS384',
        'signing_algorithm' => [
            'name' => 'RS384',
            'hash_algorithm' => 'sha384',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ]
    ],

    'RS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ]
    ],

    // ECDSA Signatures
    'ES256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES256',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha256',
            'signature_size' => 32, //
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],
    'ES384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES384',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha384',
            'signature_size' => 48, //
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],
    'ES512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'signature_size' => 64, //
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],

    // RSA-PSS Signatures
    'PS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS256',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha256',
            'salt_length' => 32, // 32 Bytes = 256 Bit (SHA-256)
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ],
    ],

    'PS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS384',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha384',
            'salt_length' => 48, // 48 Bytes = 384 Bit (SHA-384)
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ],
    ],

    'PS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS512',

        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'salt_length' => 64, // 64 Bytes = 512 Bit (SHA-512)
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ],
    ],

    // RSA Key Management
    'RSA-OAEP' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',
        'alg' => 'RSA-OAEP',

        'key_management' => [
            'padding' => OPENSSL_PKCS1_OAEP_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\RsaKeyService::class,
        ],

        'iv' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class
        ],

        'cek' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    'RSA-OAEP-256' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',
        'alg' => 'RSA-OAEP-256',

        'key_management' => [
            'padding' => OPENSSL_PKCS1_OAEP_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\RsaKeyService::class,
        ],

        'iv' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class
        ],

        'cek' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    'RSA1_5' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',
        'alg' => 'RSA1_5',

        'key_management' => [
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\RsaKeyService::class,
        ],

        'iv' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],

        'content_encryption' => [
            'name' => 'A256GCM',
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],
    ],

    // ECDH Key Management
    'ECDH-ES+A128KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'ECDSA',
        'key_management' => [
            'name' => 'ECDH-ES+A128KW',
            'bit_length' => 128,
            'hash_algorithm' => 'sha256',
            'encryptor' => EcdhEsA128KwEncryptor::class,
            'decryptor' => EcdhEsA128KwDecryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 128,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'ES256',
            'hash_algorithm' => 'sha256',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],

    'ECDH-ES+A192KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'ECDSA',
        'key_management' => [
            'name' => 'ECDH-ES+A192KW',
            'bit_length' => 192,
            'hash_algorithm' => 'sha384',
            'encryptor' => EcdhEsA192KwEncryptor::class,
            'decryptor' => EcdhEsA192KwDecryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 192,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'ES384',
            'hash_algorithm' => 'sha384',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],

    'ECDH-ES+A256KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'ECDSA',
        'key_management' => [
            'name' => 'ECDH-ES+A256KW',
            'bit_length' => 256,
            'hash_algorithm' => 'sha512',
            'encryptor' => EcdhEsA256KwEncryptor::class,
            'decryptor' => EcdhEsA256KwDecryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 256,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'ES512',
            'hash_algorithm' => 'sha512',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],

    // pbes2
    'PBES2-HS256+A128KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'HMAC',
        'key_management' => [
            'name' => 'PBES2-HS256+A128KW',
            'bit_length' => 128,
            'hash_algorithm' => 'sha256',
            'salt_length' => 16, // 16 Bytes = 128 Bit (empfohlenes Minimum)
            'encryptor' => Pbes2Hs256Encryptor::class,
            'decryptor' => Pbes2Hs256Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 128,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS256',
            'hash_algorithm' => 'sha256',
            'handle' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'PBES2-HS384+A192KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'HMAC',
        'key_management' => [
            'name' => 'PBES2-HS384+A192KW',
            'bit_length' => 192,
            'hash_algorithm' => 'sha384',
            'salt_length' => 24, // 24 Bytes = 192 Bit
            'encryptor' => Pbes2Hs384Encryptor::class,
            'decryptor' => Pbes2Hs384Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 192,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS384',
            'hash_algorithm' => 'sha384',
            'handle' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'PBES2-HS512+A256KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'HMAC',
        'key_management' => [
            'name' => 'PBES2-HS512+A256KW',
            'bit_length' => 256,
            'hash_algorithm' => 'sha512',
            'salt_length' => 32, // 32 Bytes = 256 Bit (solide Wahl, obwohl SHA-512 64 Byte ausgibt)
            'encryptor' => Pbes2Hs512Encryptor::class,
            'decryptor' => Pbes2Hs512Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 256,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS512',
            'hash_algorithm' => 'sha512',
            'handle' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    // AES Key Wrap
    'A128KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'key_management' => [
            'name' => 'A128KW',
            'bit_length' => 128,
            'encryptor' => AesKw128Encryptor::class,
            'decryptor' => AesKw128Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'iv_length' => 128,
            'cek_length' => 128,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
    ],

    'A192KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'key_management' => [
            'name' => 'A192KW',
            'bit_length' => 192,
            'encryptor' => AesKw192Encryptor::class,
            'decryptor' => AesKw192Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],

        'iv' => [
            'length' => 128,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class
        ],

        'cek' => [
            'length' => 192, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    'A256KW' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'key_management' => [
            'name' => 'A256KW',
            'bit_length' => 256,
            'encryptor' => AesKw256Encryptor::class,
            'decryptor' => AesKw256Decryptor::class,
        ],

        'content_encryption' => [
            'name' => 'dir',
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],

        'iv' => [
            'length' => 128,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class
        ],

        'cek' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    // AES GCM
    'A128GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'alg' => 'dir',
        'enc' => 'A128GCM',

        'content_encryption' => [
            'length' => 128,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],

        'iv' => [
            'length' => 96, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],

    ],

    'A192GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'alg' => 'dir',
        'enc' => 'A192GCM',

        'content_encryption' => [
            'length' => 192, // bits
            'mac_bit_length' => null,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],
        'iv' => [
            'length' => 96, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 192, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    'A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'alg' => 'dir',
        'enc' => 'A256GCM',

        'content_encryption' => [
            'length' => 256,
            'mac_bit_length' => null,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],

        'iv' => [
            'length' => 96, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    // ECDH ES ohne Wrap
    'ECDH-ES-P521' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'ECDSA',
        'key_management' => [
            'name' => 'ECDH-ES-P521',
            'bit_length' => 521,
            'hash_algorithm' => 'sha512',
            'encryptor' => EcdhEsP521Encryptor::class,
            'decryptor' => EcdhEsP521Decryptor::class,
        ],
        'content_encryption' => [
            'name' => 'dir',
            'cek_length' => 256,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
            'crypto_handler' => \Phithi92\JsonWebToken\Crypto\Content\DirectService::class,
        ],
    ],

    // AES CBC + HMAC
    'A128CBC-HS256' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'content_encryption' => [
            'name' => 'A128CBC-HS256',
            'cek_length' => 256,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\CbcHmacCekHandler::class,
            'bit_length' => 128,
            'mac_bit_length' => 256,
            'hash_algorithm' => 'sha256',
            'iv_length' => 128,
            'encryptor' => A128CbcHs256Encryptor::class,
            'decryptor' => A128CbcHs256Decryptor::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS256',
            'hash_algorithm' => 'sha256',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'A192CBC-HS384' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'content_encryption' => [
            'name' => 'A192CBC-HS384',
            'cek_length' => 384,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\CbcHmacCekHandler::class,
            'bit_length' => 192,
            'mac_bit_length' => 384,
            'hash_algorithm' => 'sha384',
            'iv_length' => 128,
            'encryptor' => A192CbcHs384Encryptor::class,
            'decryptor' => A192CbcHs384Decryptor::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS384',
            'hash_algorithm' => 'sha384',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'A256CBC-HS512' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',
        'content_encryption' => [
            'name' => 'A256CBC-HS512',
            'cek_length' => 512,
            'cek_handler' => \Phithi92\JsonWebToken\Crypto\Cek\CbcHmacCekHandler::class,
            'bit_length' => 256,
            'mac_bit_length' => 512,
            'hash_algorithm' => 'sha512',
            'iv_length' => 128,
            'encryptor' => A256CbcHs512Encryptor::class,
            'decryptor' => A256CbcHs512Decryptor::class,
        ],
        'signing_algorithm' => [
            'name' => 'HS512',
            'hash_algorithm' => 'sha512',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],
];
