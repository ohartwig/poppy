<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

use Koh\Poppy\Http\Url;

/**
 * Allow- and blocklist by client_id or by host.
 *
 * Entries are either a full client_id URL, compared exactly, or a bare host,
 * which covers every client_id on that host and its subdomains. An empty
 * allowlist means "open": any agent not blocked is accepted, which is what the
 * protocol assumes by default. A non-empty allowlist is the "registration
 * required" mode.
 */
final readonly class ListClientPolicy implements ClientPolicy
{
    /**
     * @param list<string> $allow
     * @param list<string> $block
     */
    public function __construct(
        private array $allow = [],
        private array $block = [],
    ) {}

    public function accepts(string $clientId): bool
    {
        if (self::matchesAny($clientId, $this->block)) {
            return false;
        }

        return $this->allow === [] || self::matchesAny($clientId, $this->allow);
    }

    /** @param list<string> $entries */
    private static function matchesAny(string $clientId, array $entries): bool
    {
        foreach ($entries as $entry) {
            if (str_contains($entry, '://') ? $entry === $clientId : Url::isOnDomain($clientId, $entry)) {
                return true;
            }
        }

        return false;
    }
}
