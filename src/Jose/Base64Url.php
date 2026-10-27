<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

use Koh\Poppy\Exception\InvalidJose;

/**
 * Unpadded base64url (RFC 7515 §2).
 *
 * Decoding is strict on purpose: padding, whitespace and characters from the
 * standard alphabet are rejected rather than tolerated. A lenient decoder lets
 * two different strings decode to the same bytes, and a JWS whose signing
 * input can be spelled two ways is one an attacker can re-spell.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $encoded): string
    {
        if ($encoded === '') {
            return '';
        }

        if (preg_match('/^[A-Za-z0-9_-]+$/D', $encoded) !== 1 || strlen($encoded) % 4 === 1) {
            throw InvalidJose::encoding();
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($decoded === false || self::encode($decoded) !== $encoded) {
            throw InvalidJose::encoding();
        }

        return $decoded;
    }
}
