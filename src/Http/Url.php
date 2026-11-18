<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Http;

/**
 * URL rules the protocol applies everywhere (Poppy 0.2, section 3).
 *
 * Every URL a Company publishes or accepts from a Personal Agent must be HTTPS.
 * Hosts are compared ignoring case and nothing else: no IDN folding, no
 * trailing-dot stripping, no "www." equivalence. The specification asks for
 * exactly that, and every normalization added here would be one more way for
 * two parties to disagree about which host a URL names.
 *
 * For the same reason a host is accepted only in a form every parser reads the
 * same way: letters, digits and hyphens in dot-separated labels, a dotted
 * IPv4 address, or a bracketed IPv6 address. parse_url() is more generous
 * than a browser. It takes "evil.example\.shop.example" as one host, which
 * ends in ".shop.example", while a browser reads the backslash as a slash and
 * goes to evil.example. A trailing dot names the same server under a second
 * spelling, which is one spelling too many for a blocklist. And a host whose
 * last label is a number ("127.1", "0x7f.1", "2130706433") is an IPv4
 * address to a browser and to cURL, but a name to be resolved to PHP.
 */
final class Url
{
    public static function isHttps(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https') {
            return false;
        }

        return self::isUnambiguousHost($parts['host'] ?? '') && !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['fragment'])
            && preg_match('/[\s\x00-\x1f\x7f]/', $url) !== 1;
    }

    /** The lower-cased host, or null when there is none or it is not in an unambiguous form. */
    public static function host(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && self::isUnambiguousHost($host) ? strtolower($host) : null;
    }

    private static function isUnambiguousHost(string $host): bool
    {
        if (str_starts_with($host, '[')) {
            return str_ends_with($host, ']') && filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        if (preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/Di', $host) !== 1) {
            return false;
        }

        $lastLabel = substr($host, (int) strrpos('.' . $host, '.'));

        return preg_match('/^(\d+|0x[0-9a-f]*)$/Di', $lastLabel) !== 1
            || filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /** True when $url's host is $domain or a subdomain of it. */
    public static function isOnDomain(string $url, string $domain): bool
    {
        $host = self::host($url);
        $domain = strtolower($domain);

        return $host !== null && ($host === $domain || str_ends_with($host, '.' . $domain));
    }

    /**
     * Syntax-based normalization for comparing a DPoP `htu` with the request
     * (RFC 9449 §4.3 point 9, RFC 3986 §6.2.2–6.2.3): lowercase scheme and
     * host, default port dropped, empty path as "/", query and fragment gone.
     */
    public static function normalizeForHtu(string $url): ?string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $port = $parts['port'] ?? null;
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }

        $path = $parts['path'] ?? '';

        return $scheme . '://' . strtolower($parts['host']) . ($port !== null ? ':' . $port : '') . ($path === '' ? '/' : $path);
    }
}
