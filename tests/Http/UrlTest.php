<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Http;

use Koh\Poppy\Http\Url;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UrlTest extends TestCase
{
    /** @return iterable<string, array{string, bool}> */
    public static function httpsUrls(): iterable
    {
        yield 'plain' => ['https://agent.example/agent.json', true];
        yield 'upper-case scheme' => ['HTTPS://agent.example/', true];
        yield 'with query' => ['https://agent.example/a?b=c', true];
        yield 'http' => ['http://agent.example/', false];
        yield 'no host' => ['https:///path', false];
        yield 'user info' => ['https://user@agent.example/', false];
        yield 'password' => ['https://:pw@agent.example/', false];
        yield 'fragment' => ['https://agent.example/#x', false];
        yield 'whitespace' => ['https://agent.example/a b', false];
        yield 'control character' => ["https://agent.example/a\x01", false];
        yield 'not a URL' => ['agent.example', false];
    }

    #[DataProvider('httpsUrls')]
    public function testIsHttps(string $url, bool $expected): void
    {
        self::assertSame($expected, Url::isHttps($url));
    }

    public function testHostIsLowerCased(): void
    {
        self::assertSame('agent.example', Url::host('https://Agent.EXAMPLE/x'));
        self::assertNull(Url::host('no-url'));
    }

    public function testIsOnDomain(): void
    {
        self::assertTrue(Url::isOnDomain('https://shop.example/', 'shop.example'));
        self::assertTrue(Url::isOnDomain('https://www.Shop.example/', 'SHOP.example'));
        self::assertFalse(Url::isOnDomain('https://evilshop.example/', 'shop.example'), 'a suffix is not a subdomain');
        self::assertFalse(Url::isOnDomain('https://shop.example.evil.example/', 'shop.example'));
        self::assertFalse(Url::isOnDomain('not a url', 'shop.example'));
    }

    /** @return iterable<string, array{string, string|null}> */
    public static function htus(): iterable
    {
        yield 'unchanged' => ['https://shop.example/poppy/token', 'https://shop.example/poppy/token'];
        yield 'case and default port' => ['HTTPS://Shop.Example:443/poppy/token', 'https://shop.example/poppy/token'];
        yield 'http default port' => ['http://shop.example:80/x', 'http://shop.example/x'];
        yield 'other port kept' => ['https://shop.example:8443/x', 'https://shop.example:8443/x'];
        yield 'empty path' => ['https://shop.example', 'https://shop.example/'];
        yield 'query and fragment dropped' => ['https://shop.example/x?y=1#z', 'https://shop.example/x'];
        yield 'path case kept' => ['https://shop.example/Token', 'https://shop.example/Token'];
        yield 'no host' => ['/relative', null];
    }

    #[DataProvider('htus')]
    public function testNormalizesForHtu(string $url, ?string $expected): void
    {
        self::assertSame($expected, Url::normalizeForHtu($url));
    }
}
