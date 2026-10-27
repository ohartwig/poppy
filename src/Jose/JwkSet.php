<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

use Koh\Poppy\Exception\InvalidJose;

/**
 * A JWK Set (RFC 7517 §5) as published at a Personal Agent's `jwks_uri`.
 *
 * Keys this package cannot use are skipped instead of failing the whole set: a
 * Personal Agent may publish keys for other purposes beside its signing keys,
 * and one exotic entry must not lock it out. A set with no usable key at all is
 * an error.
 */
final readonly class JwkSet
{
    private const MAX_KEYS = 32;

    /** @param list<Jwk> $keys */
    private function __construct(public array $keys) {}

    /** @param array<mixed> $set */
    public static function fromArray(array $set): self
    {
        $entries = $set['keys'] ?? null;
        if (!is_array($entries) || !array_is_list($entries)) {
            throw InvalidJose::key('key set has no keys array');
        }
        if (count($entries) > self::MAX_KEYS) {
            throw InvalidJose::key('key set too large');
        }

        $keys = [];
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            try {
                $keys[] = Jwk::fromArray($entry);
            } catch (InvalidJose) {
                continue;
            }
        }

        if ($keys === []) {
            throw InvalidJose::key('key set has no usable signature key');
        }

        return new self($keys);
    }

    /**
     * The keys that may have produced a signature with this header.
     *
     * With a `kid`, only keys carrying that id; without one, every key that
     * supports the algorithm, so a set with a single unlabelled key works.
     *
     * @return list<Jwk>
     */
    public function candidates(Algorithm $algorithm, ?string $keyId): array
    {
        return array_values(array_filter(
            $this->keys,
            static fn (Jwk $key): bool => $key->supports($algorithm) && ($keyId === null || $key->keyId === $keyId),
        ));
    }

    public function verifies(Jws $jws, Algorithm $algorithm): bool
    {
        foreach ($this->candidates($algorithm, $jws->keyId()) as $key) {
            if ($key->verify($algorithm, $jws->signingInput, $jws->signature)) {
                return true;
            }
        }

        return false;
    }
}
