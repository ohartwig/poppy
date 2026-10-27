<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Symfony\Component\RateLimiter\RateLimiterFactory;

/**
 * RateLimiter over symfony/rate-limiter, which both Sylius and TYPO3 ship.
 *
 * One factory per bucket — `token`, `revoke`, `device`, `feedback`, and the
 * integration's own such as `device-page`. A bucket without a factory is not
 * limited.
 */
final readonly class SymfonyRateLimiter implements RateLimiter
{
    /** @param array<string, RateLimiterFactory> $factories */
    public function __construct(private array $factories) {}

    public function hit(string $bucket, string $key): ?int
    {
        $factory = $this->factories[$bucket] ?? null;
        if ($factory === null) {
            return null;
        }

        $limit = $factory->create(hash('sha256', $key))->consume();
        if ($limit->isAccepted()) {
            return null;
        }

        return max(1, $limit->getRetryAfter()->getTimestamp() - time());
    }
}
