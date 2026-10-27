<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Assertion;

/** A verified browser assertion (Poppy 0.2, section 5). */
final readonly class BrowserAssertion
{
    public function __construct(
        public string $clientId,
        public string $userId,
        public string $sessionId,
        public string $returnTo,
    ) {}
}
