<?php

/**
 * Test-only Redis stub.
 *
 * This stub exists solely to allow PHPUnit tests to run on systems where the
 * PHP Redis extension (ext-redis) is not installed.
 *
 * PHPUnit creates mocks by extending the original class. If the \Redis class
 * does not exist at runtime, PHPUnit cannot create a mock and the test suite
 * fails with "Class Redis not found" — even though no real Redis server is
 * required and all interactions are fully mocked.
 *
 * To avoid introducing a hard dependency on ext-redis for contributors and CI,
 * this minimal replacement class is defined conditionally:
 *  - It is only declared if \Redis does not already exist.
 *  - It implements only the methods used in the tests.
 *  - It must NEVER be used in production code.
 *
 * Production environments are expected to use the real ext-redis extension.
 */

namespace {
    if (!class_exists(\Redis::class)) {
        class Redis
        {
            public function exists(string $key): int
            {
                return 0;
            }
            public function setex(string $key, int $ttl, string $value): bool
            {
                return true;
            }
        }
    }
}
