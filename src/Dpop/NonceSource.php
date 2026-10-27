<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Dpop;

/**
 * Server-issued DPoP nonces (RFC 9449 §8), for a Company that wants proofs
 * that cannot be made in advance.
 *
 * Optional: without a nonce source, freshness rests on `iat` and the
 * acceptance window. A stateless implementation — an HMAC over a time slot —
 * works across replicas without shared storage.
 */
interface NonceSource
{
    public function current(): string;

    public function isValid(string $nonce): bool;
}
