<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Server\BrowserCookie;
use Koh\Poppy\Server\SymfonyRateLimiter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

final class AdaptersTest extends TestCase
{
    public function testBrowserCookieRoundTripsAndRefusesForgeries(): void
    {
        $cookie = new BrowserCookie(str_repeat('s', 32));
        $value = $cookie->value('ses_abc.def');

        self::assertSame('ses_abc.def', $cookie->sessionId($value), 'a dot in the id is fine');
        self::assertNull($cookie->sessionId('ses_abc.def'), 'the bare id is not a cookie');
        self::assertNull($cookie->sessionId('ses_other' . substr($value, strrpos($value, '.') ?: 0)));
        self::assertNull($cookie->sessionId('no-dot'));
        self::assertNull($cookie->sessionId('.' . substr($value, (strrpos($value, '.') ?: 0) + 1)));
        self::assertNull((new BrowserCookie(str_repeat('t', 32)))->sessionId($value), 'another secret');

        $this->expectException(\InvalidArgumentException::class);
        new BrowserCookie(str_repeat('s', 31));
    }

    public function testSymfonyRateLimiter(): void
    {
        $factory = new RateLimiterFactory(['id' => 'token', 'policy' => 'fixed_window', 'limit' => 2, 'interval' => '1 minute'], new InMemoryStorage());
        $limiter = new SymfonyRateLimiter(['token' => $factory]);

        $first = $limiter->hit('token', 'a');
        $second = $limiter->hit('token', 'a');
        $retry = $limiter->hit('token', 'a');
        self::assertNull($first);
        self::assertNull($second);
        self::assertNotNull($retry);
        self::assertGreaterThanOrEqual(1, $retry);
        // 61, not 60: symfony/rate-limiter (8.1) answers with the window's end
        // rounded up to the whole second, so a one-minute window that opened
        // part-way through a second reports a retry 61 seconds from the start
        // of the current one. Waiting that long is never too early.
        self::assertLessThanOrEqual(61, $retry);
        self::assertNull($limiter->hit('token', 'b'), 'keys are counted apart');
        self::assertNull($limiter->hit('unconfigured', 'a'));
    }
}
