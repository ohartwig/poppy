<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Replay;

/**
 * Process-local replay guard for tests and single-process tools.
 *
 * Not for a web server: every PHP worker has its own memory, so a replay sent
 * to another worker is accepted.
 */
final class InMemoryReplayGuard implements ReplayGuard
{
    /** @var array<string, true> */
    private array $seen = [];

    public function claim(string $scope, string $id, \DateTimeImmutable $until): bool
    {
        $key = $scope . "\x00" . $id;
        if (isset($this->seen[$key])) {
            return false;
        }

        $this->seen[$key] = true;

        return true;
    }
}
