<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Jose\Base64Url;

/**
 * Random identifiers and token values, and the hash under which a token is
 * stored.
 *
 * Tokens are opaque random strings, not JWTs: the Personal Agent must not
 * depend on their content (Poppy 0.2, 4.2), and a token that is a lookup key
 * can be revoked by deleting a row instead of waiting for an expiry.
 */
final class Secrets
{
    /** RFC 8628 §6.1: no vowels, so no words; no ambiguous characters. */
    private const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public static function token(string $prefix): string
    {
        return $prefix . Base64Url::encode(random_bytes(32));
    }

    public static function id(string $prefix): string
    {
        return $prefix . Base64Url::encode(random_bytes(16));
    }

    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /** Eight characters as XXXX-XXXX: 20^8 ≈ 2.6 × 10^10 codes. */
    public static function userCode(): string
    {
        $code = '';
        for ($i = 0; $i < 8; ++$i) {
            $code .= self::USER_CODE_ALPHABET[random_int(0, strlen(self::USER_CODE_ALPHABET) - 1)];
        }

        return substr($code, 0, 4) . '-' . substr($code, 4);
    }

    /** What a User typed, in the stored form: case, spaces and dashes do not matter. */
    public static function normalizeUserCode(string $input): ?string
    {
        $code = strtoupper(preg_replace('/[\s-]+/', '', $input) ?? '');
        if (strlen($code) !== 8 || strspn($code, self::USER_CODE_ALPHABET) !== 8) {
            return null;
        }

        return substr($code, 0, 4) . '-' . substr($code, 4);
    }
}
