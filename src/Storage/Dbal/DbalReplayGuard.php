<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Storage\Dbal;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Koh\Poppy\Replay\ReplayGuard;
use Psr\Clock\ClockInterface;

/**
 * A replay guard on the primary key of a table: the INSERT is the
 * set-if-absent, and the database decides which of two racing requests wins.
 *
 * A row left behind by an id that has since expired is taken over by an
 * UPDATE that only matches while it is still expired, so the takeover is as
 * atomic as the insert. Expired rows are removed by purgeExpired().
 */
final readonly class DbalReplayGuard implements ReplayGuard
{
    public function __construct(
        private Connection $connection,
        private ClockInterface $clock,
        private string $prefix = 'koh_poppy_',
    ) {}

    public function claim(string $scope, string $id, \DateTimeImmutable $until): bool
    {
        $key = hash('sha256', $scope . "\x00" . $id);
        $table = $this->prefix . 'replay';

        try {
            $this->connection->insert($table, ['id_hash' => $key, 'expires_at' => $until->getTimestamp()]);

            return true;
        } catch (UniqueConstraintViolationException) {
            $taken = $this->connection->executeStatement(
                sprintf('UPDATE %s SET expires_at = ? WHERE id_hash = ? AND expires_at < ?', $this->connection->quoteIdentifier($table)),
                [$until->getTimestamp(), $key, $this->clock->now()->getTimestamp()],
            );

            return $taken === 1;
        }
    }

    public function purgeExpired(\DateTimeImmutable $now): void
    {
        $this->connection->executeStatement(
            sprintf('DELETE FROM %s WHERE expires_at < ?', $this->connection->quoteIdentifier($this->prefix . 'replay')),
            [$now->getTimestamp()],
        );
    }
}
