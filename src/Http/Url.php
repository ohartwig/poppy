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
 */
final class Url
{
    public static function isHttps(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https') {
            return false;
        }

        $host = $parts['host'] ?? '';

        return $host !== '' && !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['fragment'])
            && preg_match('/[\s\x00-\x1f\x7f]/', $url) !== 1;
    }

    public static function host(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? strtolower($host) : null;
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
