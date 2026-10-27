<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Jose\Base64Url;

/** PKCE with S256 only (RFC 7636); `plain` would defeat its purpose. */
final class Pkce
{
    private const VERIFIER = '/^[A-Za-z0-9\-._~]{43,128}$/D';

    private const CHALLENGE = '/^[A-Za-z0-9_-]{43}$/D';

    public static function isValidChallenge(string $challenge): bool
    {
        return preg_match(self::CHALLENGE, $challenge) === 1;
    }

    public static function verify(string $verifier, string $challenge): bool
    {
        return preg_match(self::VERIFIER, $verifier) === 1
            && hash_equals($challenge, Base64Url::encode(hash('sha256', $verifier, true)));
    }
}
