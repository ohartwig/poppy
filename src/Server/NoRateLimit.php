<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

final class NoRateLimit implements RateLimiter
{
    public function hit(string $bucket, string $key): ?int
    {
        return null;
    }
}
