<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Replay;

/**
 * Remembers one-time identifiers — assertion and DPoP `jti` values — until the
 * thing they identify has expired.
 *
 * claim() MUST be atomic: set-if-absent in one operation, such as Redis
 * `SET NX EX` or an INSERT against a unique key. "has() then set()" is two
 * operations, and two workers that both see "absent" both accept the same
 * assertion. That is not a theoretical race: a replayed assertion is sent on
 * purpose, and in parallel.
 */
interface ReplayGuard
{
    /**
     * Records $id in $scope until $until.
     *
     * @return bool true when $id was not seen in $scope before, false for a replay
     */
    public function claim(string $scope, string $id, \DateTimeImmutable $until): bool;
}
