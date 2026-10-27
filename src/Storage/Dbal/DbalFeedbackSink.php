<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Storage\Dbal;

use Doctrine\DBAL\Connection;
use Koh\Poppy\Feedback\FeedbackReport;
use Koh\Poppy\Feedback\FeedbackSink;
use Koh\Poppy\Resource\SessionContext;

/**
 * Keeps feedback reports in a table, and reads them back for an admin page.
 *
 * What is stored is what the Personal Agent wrote, unchanged and untrusted:
 * whoever renders latest() escapes it, and nothing feeds it to a model as
 * instructions (Poppy 0.2, section 8).
 */
final readonly class DbalFeedbackSink implements FeedbackSink
{
    public function __construct(
        private Connection $connection,
        private string $prefix = 'koh_poppy_',
    ) {}

    public function record(FeedbackReport $report, SessionContext $session, \DateTimeImmutable $receivedAt): void
    {
        $this->connection->insert($this->prefix . 'feedback', [
            'client_id' => $session->clientId,
            'user_id' => $session->userId,
            'session_id' => $session->sessionId,
            'signed_in' => $session->isSignedIn() ? 1 : 0,
            'kind' => $report->kind,
            'task' => $report->task,
            'description' => $report->description,
            'received_at' => $receivedAt->getTimestamp(),
        ]);
    }

    /**
     * @return list<array{client_id: string, kind: string, task: string, description: string, signed_in: bool, received_at: \DateTimeImmutable}>
     */
    public function latest(int $limit = 100): array
    {
        $rows = $this->connection->createQueryBuilder()
            ->select('client_id', 'kind', 'task', 'description', 'signed_in', 'received_at')
            ->from($this->prefix . 'feedback')
            ->orderBy('received_at', 'DESC')
            ->addOrderBy('id', 'DESC')
            ->setMaxResults(max(1, $limit))
            ->executeQuery()
            ->fetchAllAssociative();

        return array_map(static fn (array $row): array => [
            'client_id' => is_string($row['client_id']) ? $row['client_id'] : '',
            'kind' => is_string($row['kind']) ? $row['kind'] : '',
            'task' => is_string($row['task']) ? $row['task'] : '',
            'description' => is_string($row['description']) ? $row['description'] : '',
            'signed_in' => (bool) $row['signed_in'],
            'received_at' => new \DateTimeImmutable('@' . (is_numeric($row['received_at']) ? (int) $row['received_at'] : 0)),
        ], $rows);
    }
}
