<?php

declare(strict_types=1);

use Phithi92\JsonWebToken\Crypto\Content\AesGcmHandler;
use Phithi92\JsonWebToken\Crypto\Content\ContentEncryptionHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Iv\IvHandler;
use Phithi92\JsonWebToken\Crypto\Iv\IvHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Key\KeyHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Key\RsaKeyHandler;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekHandler;
use Phithi92\JsonWebToken\Crypto\KeyManagement\CekHandlerInterface;
use Phithi92\JsonWebToken\Crypto\Signature\EcdsaSignatureHandler;
use Phithi92\JsonWebToken\Crypto\Signature\HmacSignatureHandler;
use Phithi92\JsonWebToken\Crypto\Signature\RsaSignatureHandler;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureHandlerInterface;

return [

    // HMAC Signatures
    'HS256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS256',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha256',
            'handler' => HmacSignatureHandler::class,
        ],
    ],

    'HS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'handler' => HmacSignatureHandler::class,
        ],
    ],

    'HS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'HMAC',
        'alg' => 'HS512',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'handler' => HmacSignatureHandler::class,
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
            'handler' => RsaSignatureHandler::class,
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
            'handler' => RsaSignatureHandler::class,
        ],
    ],

    'RS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'RS512',
        SignatureHandlerInterface::class => [
            'name' => 'RS512',
            'hash_algorithm' => 'sha512',
            'padding' => OPENSSL_PKCS1_PADDING,
            'handler' => RsaSignatureHandler::class,
        ],
    ],

    // ECDSA Signatures
    'ES256' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES256',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha256',
            'handler' => EcdsaSignatureHandler::class,
        ],
    ],
    'ES384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'handler' => EcdsaSignatureHandler::class,
        ],
    ],
    'ES512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'ECDSA',
        'alg' => 'ES512',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'handler' => EcdsaSignatureHandler::class,
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
            'handler' => RsaSignatureHandler::class,
        ],
    ],

    'PS384' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS384',
        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha384',
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => RsaSignatureHandler::class,
        ],
    ],

    'PS512' => [
        'token_type' => 'JWS',
        'algorithm_type' => 'RSA',
        'alg' => 'PS512',

        SignatureHandlerInterface::class => [
            'hash_algorithm' => 'sha512',
            'padding' => defined('OPENSSL_PKCS1_PSS_PADDING') ? OPENSSL_PKCS1_PSS_PADDING : 6,
            'handler' => RsaSignatureHandler::class,
        ],
    ],

    // RSA Key Management
    'RSA-OAEP/A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP',
        'enc' => 'A256GCM',

        KeyHandlerInterface::class => [
            'hash' => 'sha1',
            'padding' => phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => RsaKeyHandler::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvHandler::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256, // bits
            'strict_length' => true,
            'handler' => CekHandler::class,
        ],

        ContentEncryptionHandlerInterface::class => [
            'length' => 256, // bits
            'handler' => AesGcmHandler::class,
        ],
    ],

    'RSA-OAEP-256/A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'RSA',

        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256GCM',

        KeyHandlerInterface::class => [
            'hash' => 'sha256',
            'padding' => phpseclib3\Crypt\RSA::ENCRYPTION_OAEP,
            'handler' => RsaKeyHandler::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvHandler::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256, // bits
            'strict_length' => true,
            'handler' => CekHandler::class,
        ],

        ContentEncryptionHandlerInterface::class => [
            'length' => 256, // bits
            'handler' => AesGcmHandler::class,
        ],
    ],

    // AES GCM
    'A128GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A128GCM',

        ContentEncryptionHandlerInterface::class => [
            'length' => 128,
            'handler' => AesGcmHandler::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvHandler::class,
        ],

        CekHandlerInterface::class => [
            'length' => 128, // bits
            'strict_length' => true,
            'handler' => CekHandler::class,
        ],
    ],

    'A192GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A192GCM',

        ContentEncryptionHandlerInterface::class => [
            'length' => 192,
            'mac_bit_length' => null,
            'handler' => AesGcmHandler::class,
        ],
        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvHandler::class,
        ],

        CekHandlerInterface::class => [
            'length' => 192,
            'strict_length' => true,
            'handler' => CekHandler::class,
        ],
    ],

    'A256GCM' => [
        'token_type' => 'JWE',
        'algorithm_type' => 'AES',

        'alg' => 'dir',
        'enc' => 'A256GCM',

        ContentEncryptionHandlerInterface::class => [
            'length' => 256,
            'mac_bit_length' => null,
            'handler' => AesGcmHandler::class,
        ],

        IvHandlerInterface::class => [
            'length' => 96, // bits
            'handler' => IvHandler::class,
        ],

        CekHandlerInterface::class => [
            'length' => 256,
            'strict_length' => true,
            'handler' => CekHandler::class,
        ],
    ],
];
