<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Exception\PoppyError;

/**
 * Account scopes (Poppy 0.2, 4.4).
 *
 * `poppy:read` and `poppy:write` are the protocol's own; a Company may add
 * scopes of its own, which must not start with `poppy:`.
 */
final class Scopes
{
    public const READ = 'poppy:read';

    public const WRITE = 'poppy:write';

    /** RFC 6749 §3.3 scope-token: %x21 / %x23-5B / %x5D-7E. */
    private const TOKEN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

    /**
     * Parses a space-separated scope string. Unknown and malformed scopes are
     * an error, never silently dropped: a Personal Agent that asked for
     * something it cannot get must learn it now, not at the first refused call.
     *
     * @param list<string> $allowed
     *
     * @return list<string>
     *
     * @throws PoppyError invalid_scope
     */
    public static function parse(mixed $value, array $allowed, bool $required = true): array
    {
        if ($value === null || $value === '') {
            if ($required) {
                throw PoppyError::invalidScope('scope is required');
            }

            return [];
        }
        if (!is_string($value)) {
            throw PoppyError::invalidScope('scope must be a space-separated string');
        }

        $scopes = [];
        foreach (explode(' ', $value) as $scope) {
            if ($scope === '' || preg_match(self::TOKEN, $scope) !== 1) {
                throw PoppyError::invalidScope('scope is malformed');
            }
            if (!in_array($scope, $allowed, true)) {
                throw PoppyError::invalidScope('scope is unknown or not available here');
            }
            $scopes[$scope] = true;
        }

        return array_keys($scopes);
    }

    /** @param list<string> $scopes */
    public static function format(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    public static function isValidCustom(string $scope): bool
    {
        return preg_match(self::TOKEN, $scope) === 1 && !str_starts_with($scope, 'poppy:');
    }
}
