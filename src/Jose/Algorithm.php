<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

/**
 * The asymmetric JWS algorithms this package verifies.
 *
 * There is no `none` and no HMAC: every signature in the protocol is checked
 * against a public key the signer published, and a shared-secret algorithm
 * would let anyone who knows the public key forge one. RSASSA-PSS is left out
 * because ext-openssl cannot verify it through openssl_verify().
 *
 * ES256 is the one every Company must accept (Poppy 0.2, 3.2), so it is also
 * the only algorithm a default configuration needs.
 */
enum Algorithm: string
{
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case RS256 = 'RS256';
    case EdDSA = 'EdDSA';
    case Ed25519 = 'Ed25519';

    public static function tryFromHeader(mixed $value): ?self
    {
        return is_string($value) ? self::tryFrom($value) : null;
    }

    /**
     * @param list<self> $algorithms
     *
     * @return list<string>
     */
    public static function names(array $algorithms): array
    {
        return array_map(static fn (self $algorithm): string => $algorithm->value, $algorithms);
    }

    /** Length of a raw R || S signature, for the ECDSA algorithms. */
    public function ecSignatureLength(): ?int
    {
        return match ($this) {
            self::ES256 => 64,
            self::ES384 => 96,
            default => null,
        };
    }

    public function curve(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::EdDSA, self::Ed25519 => 'Ed25519',
            self::RS256 => null,
        };
    }

    public function keyType(): string
    {
        return match ($this) {
            self::ES256, self::ES384 => 'EC',
            self::RS256 => 'RSA',
            self::EdDSA, self::Ed25519 => 'OKP',
        };
    }

    public function digest(): int
    {
        return match ($this) {
            self::ES384 => OPENSSL_ALGO_SHA384,
            default => OPENSSL_ALGO_SHA256,
        };
    }
}
