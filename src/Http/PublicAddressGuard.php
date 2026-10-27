<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Http;

use Koh\Poppy\Exception\FetchFailed;

/**
 * Resolves the host and refuses any address that is not public unicast.
 *
 * This is a pre-flight check, and it has the gap every pre-flight check has:
 * the HTTP client resolves the name again, and a hostile DNS server can answer
 * differently the second time. Use it together with an HTTP client that pins
 * or re-checks the connected address — Symfony's NoPrivateNetworkHttpClient,
 * or a Guzzle handler with CURLOPT_RESOLVE. The integrations do. On its own it
 * still stops the plain case, a client_id that simply names an internal host.
 */
final readonly class PublicAddressGuard implements AddressGuard
{
    /** @var \Closure(string): list<string> */
    private \Closure $resolver;

    /** @param (\Closure(string): list<string>)|null $resolver host → IP addresses, for tests */
    public function __construct(?\Closure $resolver = null)
    {
        $this->resolver = $resolver ?? self::resolve(...);
    }

    public function assertAllowed(string $url): void
    {
        if (!Url::isHttps($url)) {
            throw FetchFailed::notHttps();
        }

        $port = parse_url($url, PHP_URL_PORT);
        if ($port !== null && $port !== 443) {
            throw FetchFailed::forbiddenAddress();
        }

        $host = (string) Url::host($url);
        $literal = trim($host, '[]');
        $addresses = filter_var($literal, FILTER_VALIDATE_IP) !== false ? [$literal] : ($this->resolver)($host);

        if ($addresses === []) {
            throw FetchFailed::unresolvable();
        }

        foreach ($addresses as $address) {
            if (!self::isPublic($address)) {
                throw FetchFailed::forbiddenAddress();
            }
        }
    }

    public static function isPublic(string $address): bool
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        $packed = inet_pton($address);
        if ($packed === false) {
            return false;
        }

        // PHP's lists already refuse ::, ::1, IPv4-mapped ::ffff:0:0/96, unique
        // local fc00::/7, link-local fe80::/10 and the IPv4 private and reserved
        // ranges; the tests pin that, so a PHP that stops doing it fails them.
        // What PHP lets through is checked here.
        if (strlen($packed) === 16) {
            $first = ord($packed[0]);
            $second = ord($packed[1]);

            return !(
                ($first === 0xfe && ($second & 0xc0) === 0xc0) // fec0::/10 site-local (deprecated)
                || $first === 0xff                             // multicast
                || str_starts_with($packed, "\x00\x64\xff\x9b") // 64:ff9b::/96 NAT64 may reach anything
                || str_starts_with($packed, "\x20\x01\x0d\xb8") // 2001:db8::/32 documentation
            );
        }

        // 100.64.0.0/10 (carrier-grade NAT) is not in PHP's reserved list.
        $first = ord($packed[0]);
        $second = ord($packed[1]);

        return !($first === 100 && ($second & 0xc0) === 64) && $first < 224;
    }

    /** @return list<string> */
    private static function resolve(string $host): array
    {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (!is_array($records)) {
            return [];
        }

        $addresses = [];
        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address)) {
                $addresses[] = $address;
            }
        }

        return $addresses;
    }
}
