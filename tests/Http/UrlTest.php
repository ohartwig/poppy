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
        yield 'single label' => ['https://localhost/', true];
        yield 'hyphen and digits' => ['https://eu-1.agent2.example/', true];
        yield 'punycode' => ['https://xn--mnchen-3ya.example/', true];
        yield 'IPv4 literal' => ['https://93.184.216.34/', true];
        yield 'IPv6 literal' => ['https://[2606:2800:220:1::1]/', true];
        yield 'port' => ['https://agent.example:8443/', true];
        yield 'backslash in the host' => ['https://evil.example\.shop.example/', false];
        yield 'trailing dot' => ['https://agent.example./', false];
        yield 'leading dot' => ['https://.agent.example/', false];
        yield 'empty label' => ['https://agent..example/', false];
        yield 'label starts with a hyphen' => ['https://-agent.example/', false];
        yield 'label ends with a hyphen' => ['https://agent-.example/', false];
        yield 'underscore' => ['https://agent_1.example/', false];
        yield 'comma' => ['https://agent.example,shop.example/', false];
        yield 'percent-encoded' => ['https://agent%2eexample/', false];
        yield 'raw non-ASCII' => ['https://münchen.example/', false];
        yield 'newline after the host' => ["https://agent.example\n", false];
        yield 'short IPv4 form' => ['https://127.1/', false];
        yield 'hex IPv4 form' => ['https://0x7f.1/', false];
        yield 'upper-case hex IPv4 form' => ['https://0X7F.0.0.1/', false];
        yield 'bare 0x' => ['https://agent.0x/', false];
        yield 'integer IPv4 form' => ['https://2130706433/', false];
        yield 'octal IPv4 form' => ['https://0177.0.0.1/', false];
        yield 'numeric last label on a name' => ['https://agent.example.123/', false];
        yield 'number-like label that is not last' => ['https://123.0x7f.example/', true];
        yield 'last label only starts with digits' => ['https://agent.1a/', true];
        yield 'unbracketed junk in brackets' => ['https://[agent.example]/', false];
        yield 'IPv4 in brackets' => ['https://[127.0.0.1]/', false];
        yield 'unclosed bracket' => ['https://[::1/', false];
        yield 'IPv6 loopback literal' => ['https://[::1]/', true];
        yield 'IPv6 literal ending in ::' => ['https://[1::]/', true];
        yield 'last label only ends with digits' => ['https://agent.a1/', true];
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
        self::assertSame('[2606:2800:220:1::1]', Url::host('https://[2606:2800:220:1::1]/'));
        self::assertNull(Url::host('https://evil.example\.shop.example/'), 'a host a browser reads differently is no host');
        self::assertNull(Url::host('https://agent.example./'));
        self::assertNull(Url::host('https://127.1/'));
    }

    public function testIsOnDomain(): void
    {
        self::assertTrue(Url::isOnDomain('https://shop.example/', 'shop.example'));
        self::assertTrue(Url::isOnDomain('https://www.Shop.example/', 'SHOP.example'));
        self::assertFalse(Url::isOnDomain('https://evilshop.example/', 'shop.example'), 'a suffix is not a subdomain');
        self::assertFalse(Url::isOnDomain('https://shop.example.evil.example/', 'shop.example'));
        self::assertFalse(Url::isOnDomain('not a url', 'shop.example'));
        self::assertFalse(Url::isOnDomain('https://evil.example\.shop.example/', 'shop.example'), 'a browser goes to evil.example');
        self::assertFalse(Url::isOnDomain('https://shop.example./', 'shop.example'));
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
