<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Assertion;

use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Jose\JwkSet;

/**
 * The checks every assertion a Personal Agent signs has in common.
 *
 * Each method returns the reason it failed, or null. The caller decides which
 * OAuth error that becomes — the same broken lifetime is `invalid_client` in a
 * client assertion and `invalid_grant` in a Session assertion.
 *
 * @internal
 */
final class JwtChecks
{
    /** Clock difference tolerated between the Personal Agent and this server. */
    public const LEEWAY = 30;

    /** 128 random bits are 22 base64url characters; anything shorter cannot carry them. */
    private const MIN_JTI_LENGTH = 22;

    private const MAX_JTI_LENGTH = 256;

    /** @param list<Algorithm> $algorithms */
    public static function signature(Jws $jws, JwkSet $keys, array $algorithms): ?string
    {
        $algorithm = $jws->algorithm();
        if ($algorithm === null || !in_array($algorithm, $algorithms, true)) {
            return 'signature algorithm not accepted';
        }

        return $keys->verifies($jws, $algorithm) ? null : 'signature does not verify with the Personal Agent\'s keys';
    }

    /**
     * `aud` must be the expected value as a single string. An array is refused
     * even when it holds only that value (Poppy 0.2, 4.1 and 4.2).
     */
    public static function audience(Jws $jws, string $expected): ?string
    {
        $audience = $jws->claims['aud'] ?? null;

        return is_string($audience) && $audience === $expected ? null : 'aud must be exactly ' . $expected;
    }

    public static function lifetime(Jws $jws, \DateTimeImmutable $now, int $maxLifetime): ?string
    {
        $issuedAt = $jws->integer('iat');
        $expiresAt = $jws->integer('exp');
        if ($issuedAt === null || $expiresAt === null) {
            return 'iat and exp are required integers';
        }

        $time = $now->getTimestamp();
        if ($issuedAt > $time + self::LEEWAY) {
            return 'issued in the future';
        }
        if ($expiresAt <= $time - self::LEEWAY) {
            return 'expired';
        }
        if ($expiresAt <= $issuedAt || $expiresAt - $issuedAt > $maxLifetime) {
            return sprintf('exp must be at most %d seconds after iat', $maxLifetime);
        }

        return null;
    }

    public static function jti(Jws $jws): ?string
    {
        $jti = $jws->string('jti');
        if ($jti === null || strlen($jti) < self::MIN_JTI_LENGTH || strlen($jti) > self::MAX_JTI_LENGTH) {
            return 'jti must carry at least 128 random bits';
        }

        return null;
    }

    /** When a one-time id may be forgotten: after the assertion has expired, plus the leeway. */
    public static function rememberUntil(Jws $jws): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . ((int) $jws->integer('exp') + self::LEEWAY));
    }
}
