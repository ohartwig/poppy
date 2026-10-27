<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Feedback;

use Koh\Poppy\Exception\PoppyError;

/**
 * A Personal Agent's report of a task the Company does not offer (Poppy 0.2,
 * section 8).
 *
 * The text is untrusted and possibly written to mislead. Whoever shows it —
 * an admin grid, a mail, a model summarising a week of reports — must treat
 * it as data and never as instructions.
 */
final readonly class FeedbackReport
{
    private const MAX_TASK = 200;

    private const MAX_DESCRIPTION = 2000;

    private function __construct(
        public string $kind,
        public string $task,
        public string $description,
    ) {}

    /** @throws PoppyError invalid_request */
    public static function fromJson(string $body): self
    {
        try {
            $data = json_decode($body, true, 4, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw PoppyError::invalidRequest('The report is not JSON.');
        }

        if (!is_array($data)) {
            throw PoppyError::invalidRequest('The report must be a JSON object.');
        }

        $kind = $data['kind'] ?? null;
        $task = $data['task'] ?? null;
        $description = $data['description'] ?? null;
        // Kinds this version does not know are accepted (section 8), so later versions can add them.
        if (!is_string($kind) || $kind === '' || strlen($kind) > 64 || !is_string($task) || !is_string($description)) {
            throw PoppyError::invalidRequest('kind, task and description are required strings.');
        }

        $task = trim($task);
        $description = trim($description);
        if ($task === '' || $description === '' || mb_strlen($task) > self::MAX_TASK || mb_strlen($description) > self::MAX_DESCRIPTION) {
            throw PoppyError::invalidRequest('task takes at most 200 characters, description at most 2,000.');
        }
        if (!mb_check_encoding($task . $description, 'UTF-8')) {
            throw PoppyError::invalidRequest('The report is not valid UTF-8.');
        }

        return new self($kind, $task, $description);
    }
}
