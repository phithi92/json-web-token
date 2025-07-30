<?php

declare(strict_types=1);

return [

    // HMAC Signatures
    'HS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS256',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha256',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'HS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS384',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha384',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
    ],

    'HS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\HmacService::class,
        ],
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
        ],
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
        ],
    ],

    'RS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ],
    ],

    // ECDSA Signatures
    'ES256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES256',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha256',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],
    'ES384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES384',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha384',
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\EcdsaService::class,
        ],
    ],
    'ES512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES512',
        'signing_algorithm' => [
            'hash_algorithm' => 'sha512',
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
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => \Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService::class,
        ],
    ],

    // RSA Key Management
    'RSA-OAEP_A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP',
        'enc' => 'A256GCM',

        'key_management' => [
            'hash' => 'sha1',
            'padding' => \phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\PhpseclibRsaEncryptionService::class,
        ],

        'iv' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 256, // bits
            'strict_length' => false,
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],

        'content_encryption' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],
    ],

    'RSA-OAEP-256_A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256GCM',

        'key_management' => [
            'hash' => 'sha256',
            'padding' => \phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\PhpseclibRsaEncryptionService::class,
        ],

        'iv' => [
            'length' => 128, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 256, // bits
            'strict_length' => false,
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],

        'content_encryption' => [
            'length' => 256, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],
    ],

    'RSA1_5_A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA1_5',
        'enc' => 'A256GCM',

        'key_management' => [
            'padding' => \phpseclib3\Crypt\RSA::ENCRYPTION_PKCS1,
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\PhpseclibRsaEncryptionService::class,
        ],

        'iv' => [
            'length' => 128,
        // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 256, // bits
            'strict_length' => false,
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],

        'content_encryption' => [
            'length' => 256,
        // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
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
            'length' => 96,// bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 128,// bits
            'strict_length' => false,
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],

    'A192GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A192GCM',

        'content_encryption' => [
            'length' => 192,
            'mac_bit_length' => null,
            'handler' => \Phithi92\JsonWebToken\Crypto\Content\AesGcmService::class,
        ],
        'iv' => [
            'length' => 96, // bits
            'handler' => \Phithi92\JsonWebToken\Crypto\Encryption\IvService::class,
        ],

        'cek' => [
            'length' => 192,
            'strict_length' => false,
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
            'length' => 256,
            'strict_length' => false,
            'handler' => \Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler::class,
        ],
    ],
];
