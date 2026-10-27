<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Dpop;

use Koh\Poppy\Jose\Base64Url;
use Psr\Clock\ClockInterface;

/**
 * Stateless nonces: an HMAC over the current time slot.
 *
 * Every replica with the same secret issues and accepts the same nonces
 * without talking to each other. A nonce stays valid for its own slot and the
 * one after, so a proof made at the end of a slot still arrives in time.
 */
final readonly class TimeSlotNonceSource implements NonceSource
{
    private const MIN_SECRET_BYTES = 32;

    public function __construct(
        private string $secret,
        private ClockInterface $clock,
        private int $slotSeconds = 300,
    ) {
        if (strlen($secret) < self::MIN_SECRET_BYTES) {
            throw new \InvalidArgumentException('The nonce secret must be at least 32 bytes.');
        }
        if ($slotSeconds < 30) {
            throw new \InvalidArgumentException('A nonce slot must last at least 30 seconds.');
        }
    }

    public function current(): string
    {
        return $this->forSlot($this->slot());
    }

    public function isValid(string $nonce): bool
    {
        $slot = $this->slot();

        return hash_equals($this->forSlot($slot), $nonce) || hash_equals($this->forSlot($slot - 1), $nonce);
    }

    private function slot(): int
    {
        return intdiv($this->clock->now()->getTimestamp(), $this->slotSeconds);
    }

    private function forSlot(int $slot): string
    {
        return Base64Url::encode(hash_hmac('sha256', 'poppy-dpop-nonce|' . $slot, $this->secret, true));
    }
}
