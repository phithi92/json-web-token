<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__ . '/../src',
        __DIR__ . '/../tests',
    ]);

return (new PhpCsFixer\Config())
    ->setRules([
        '@PSR12' => true,

        'global_namespace_import' => [
            'import_classes' => true,
            'import_functions' => true,
            'import_constants' => true,
        ],
        'no_unused_imports' => true,
        'ordered_imports' => [
            'imports_order' => ['class', 'function', 'const'],
            'sort_algorithm' => 'alpha',
        ],
        'blank_line_between_import_groups' => true,
    ])
    ->setFinder($finder);
