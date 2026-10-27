<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Feedback;

use Koh\Poppy\Resource\SessionContext;

/** Where reports go: a table, a ticket queue, a log. Implemented by the integration. */
interface FeedbackSink
{
    public function record(FeedbackReport $report, SessionContext $session, \DateTimeImmutable $receivedAt): void;
}
