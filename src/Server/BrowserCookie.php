<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Jose\Base64Url;

/**
 * The value of the cookie that ties a Personal Agent's browser to its Session
 * (Poppy 0.2, section 5).
 *
 * A Session id is not a credential — the specification says so, and Personal
 * Agents put it into assertions and logs — so the cookie cannot simply carry
 * it. It carries the id with an HMAC under an application secret: without the
 * secret no one can make a cookie for a Session they only know the id of.
 * Everything else the cookie must do (follow sign-in and sign-out, never
 * outlive the Session) comes from reading the Session on every request.
 */
final readonly class BrowserCookie
{
    private const MIN_SECRET_BYTES = 32;

    public function __construct(#[\SensitiveParameter] private string $secret)
    {
        if (strlen($secret) < self::MIN_SECRET_BYTES) {
            throw new \InvalidArgumentException('The cookie secret must be at least 32 bytes.');
        }
    }

    public function value(string $sessionId): string
    {
        return $sessionId . '.' . $this->mac($sessionId);
    }

    /** The Session id in a cookie this application issued, or null for anything else. */
    public function sessionId(string $value): ?string
    {
        $dot = strrpos($value, '.');
        if ($dot === false) {
            return null;
        }

        $sessionId = substr($value, 0, $dot);

        return $sessionId !== '' && hash_equals($this->mac($sessionId), substr($value, $dot + 1)) ? $sessionId : null;
    }

    private function mac(string $sessionId): string
    {
        return Base64Url::encode(hash_hmac('sha256', 'poppy-browser-cookie|' . $sessionId, $this->secret, true));
    }
}
