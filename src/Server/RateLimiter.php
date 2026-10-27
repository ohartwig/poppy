<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

/**
 * Rate limiting by key — a client_id, or a client address on the pages a
 * person uses. Implemented by the integration with the framework's limiter.
 */
interface RateLimiter
{
    /** @return int|null seconds until the next attempt is allowed, or null when this one is */
    public function hit(string $bucket, string $key): ?int;
}
