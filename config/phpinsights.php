<?php

declare(strict_types=1);

use NunoMaduro\PhpInsights\Domain\Insights\ForbiddenNormalClasses;
use NunoMaduro\PhpInsights\Domain\Insights\ForbiddenTraits;
use SlevomatCodingStandard\Sniffs\Classes\SuperfluousAbstractClassNamingSniff;
use SlevomatCodingStandard\Sniffs\Classes\SuperfluousExceptionNamingSniff;
use SlevomatCodingStandard\Sniffs\Classes\SuperfluousInterfaceNamingSniff;
use SlevomatCodingStandard\Sniffs\Classes\SuperfluousTraitNamingSniff;
use SlevomatCodingStandard\Sniffs\TypeHints\DisallowMixedTypeHintSniff;

return [

    'preset' => 'default',

    'ide' => null,

    'exclude' => [
        'vendor',
        'bin',
    ],

    'remove' => [
        SuperfluousInterfaceNamingSniff::class,
        SuperfluousTraitNamingSniff::class,
        SuperfluousExceptionNamingSniff::class,
        SuperfluousAbstractClassNamingSniff::class,
    ],

    'config' => [
        ForbiddenTraits::class => [
            'exclude' => [
                'src/Exceptions/ErrorMessageTrait.php',
            ],
        ],
        ForbiddenNormalClasses::class => [
            'exclude' => [
                'src/Exceptions',
            ],
        ],
        DisallowMixedTypeHintSniff::class => [
            'exclude' => [
                'src/Utilities/JsonEncoder.php',
                'src/Token/Validator/ClaimValidator.php',
                'src/Token/JwtPayload.php',

            ],
        ],
    ],

    'requirements' => [
        'min-quality' => 90,
        'min-complexity' => 0,
        'min-architecture' => 90,
        'min-style' => 90,
        'disable-security-check' => false,
    ],
];
