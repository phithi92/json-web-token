<?php

declare(strict_types=1);

return [

    'preset' => 'default',

    'ide' => null,

    'exclude' => [
        'vendor',
        'storage',
        'bootstrap/cache',
    ],

    'add' => [

    ],

    'remove' => [
        // Entfernt das Beanstanden von Suffixen wie Interface, Trait, Exception
        SlevomatCodingStandard\Sniffs\Classes\SuperfluousInterfaceNamingSniff::class,
        SlevomatCodingStandard\Sniffs\Classes\SuperfluousTraitNamingSniff::class,
        SlevomatCodingStandard\Sniffs\Classes\SuperfluousExceptionNamingSniff::class,
        ForbiddenNormalClasses::class,
    ],

    'config' => [

    ],

    'requirements' => [
        'min-quality' => 90,
        'min-complexity' => 0,
        'min-architecture' => 80,
        'min-style' => 90,
        'disable-security-check' => false,
    ],
];
