<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Http;

/**
 * Where fetched client metadata and key sets are kept between requests.
 *
 * Two methods instead of PSR-16, because TYPO3 offers no PSR-16 pool out of the
 * box and Symfony offers one only through an adapter. A lost entry costs one
 * fetch; nothing here needs to be atomic.
 */
interface DocumentCache
{
    /** @return array<string, mixed>|null */
    public function get(string $key): ?array;

    /** @param array<string, mixed> $document */
    public function set(string $key, array $document, int $ttl): void;
}
