<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Exception;

/**
 * A JWS, JWK or key set that cannot be used.
 *
 * The messages name the rule that failed, never the offending value: they end
 * up in logs, and the value may be a token.
 */
final class InvalidJose extends \RuntimeException
{
    public static function encoding(): self
    {
        return new self('Not valid unpadded base64url.');
    }

    public static function structure(string $reason): self
    {
        return new self('Malformed JWS: ' . $reason . '.');
    }

    public static function key(string $reason): self
    {
        return new self('Unusable JWK: ' . $reason . '.');
    }
}
