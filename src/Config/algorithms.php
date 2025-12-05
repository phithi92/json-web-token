<?php

declare(strict_types=1);

use Phithi92\JsonWebToken\Crypto\Cek\DefaultCekHandler;
use Phithi92\JsonWebToken\Crypto\Content\AesGcmService;
use Phithi92\JsonWebToken\Crypto\Encryption\IvService;
use Phithi92\JsonWebToken\Crypto\Encryption\PhpseclibRsaEncryptionService;
use Phithi92\JsonWebToken\Crypto\Signature\EcdsaService;
use Phithi92\JsonWebToken\Crypto\Signature\HmacService;
use Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureService;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

return [

    // HMAC Signatures
    'HS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS256',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha256',
            'handler' => HmacService::class,
        ],
    ],

    'HS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'handler' => HmacService::class,
        ],
    ],

    'HS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS512',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'handler' => HmacService::class,
        ],
    ],

    // RSA Signatures
    'RS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS256',
        SignatureHandlerInterface::class => [
            'name' => 'RS256',
            'hash_algorithm' => 'sha256',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => RsaSignatureService::class,
        ],
    ],

    'RS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS384',
        SignatureHandlerInterface::class => [
            'name' => 'RS384',
            'hash_algorithm' => 'sha384',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => RsaSignatureService::class,
        ],
    ],

    'RS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS512',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => RsaSignatureService::class,
        ],
    ],

    // ECDSA Signatures
    'ES256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES256',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha256',
            'handler' => EcdsaService::class,
        ],
    ],
    'ES384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'handler' => EcdsaService::class,
        ],
    ],
    'ES512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES512',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'handler' => EcdsaService::class,
        ],
    ],

    // RSA-PSS Signatures
    'PS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS256',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha256',
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => RsaSignatureService::class,
        ],
    ],

    'PS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => RsaSignatureService::class,
        ],
    ],

    'PS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS512',

        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => RsaSignatureService::class,
        ],
    ],

    // RSA Key Management
    'RSA-OAEP_A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP',
        'enc' => 'A256GCM',

        KeyHandlerInterface::class => [
            'hash' => 'sha1',
            'padding' => phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => PhpseclibRsaEncryptionService::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvService::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256, // bits
            'strict_length' => true,
            'handler' => DefaultCekHandler::class,
        ],

        PayloadHandlerInterface::class => [
            'length' => 256, // bits
            'handler' => AesGcmService::class,
        ],
    ],

    'RSA-OAEP-256_A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256GCM',

        KeyHandlerInterface::class => [
            'hash' => 'sha256',
            'padding' => phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => PhpseclibRsaEncryptionService::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvService::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256, // bits
            'strict_length' => true,
            'handler' => DefaultCekHandler::class,
        ],

        PayloadHandlerInterface::class => [
            'length' => 256, // bits
            'handler' => AesGcmService::class,
        ],
    ],

    // AES GCM
    'A128GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A128GCM',

        PayloadHandlerInterface::class => [
            'length' => 128,
            'handler' => AesGcmService::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvService::class,
        ],

        CekHandlerInterface::class => [
            'length' => 128, // bits
            'strict_length' => true,
            'handler' => DefaultCekHandler::class,
        ],
    ],

    'A192GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A192GCM',

        PayloadHandlerInterface::class => [
            'length' => 192,
            'mac_bit_length' => null,
            'handler' => AesGcmService::class,
        ],
        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvService::class,
        ],

        CekHandlerInterface::class => [
            'length' => 192,
            'strict_length' => true,
            'handler' => DefaultCekHandler::class,
        ],
    ],

    'A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A256GCM',

        PayloadHandlerInterface::class => [
            'length' => 256,
            'mac_bit_length' => null,
            'handler' => AesGcmService::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvService::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256,
            'strict_length' => true,
            'handler' => DefaultCekHandler::class,
        ],
    ],
];
