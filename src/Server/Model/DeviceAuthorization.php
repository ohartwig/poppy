<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

/**
 * A Device Sign-In in progress (RFC 8628, Poppy 0.2 4.6).
 *
 * The device code is the Personal Agent's secret and is stored as a hash. The
 * user code is shown to the User and typed in by hand, so it is stored as is
 * and looked up by value; its short alphabet is why the verification page
 * must be rate-limited.
 */
final readonly class DeviceAuthorization
{
    /**
     * @param list<string> $requestedScopes
     * @param list<string> $grantedScopes
     */
    public function __construct(
        public string $deviceCodeHash,
        public string $userCode,
        public string $clientId,
        public array $requestedScopes,
        public \DateTimeImmutable $expiresAt,
        public int $interval,
        public DeviceStatus $status = DeviceStatus::Pending,
        public ?string $accountId = null,
        public array $grantedScopes = [],
        public ?\DateTimeImmutable $lastPolledAt = null,
    ) {}

    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /** @param list<string> $grantedScopes */
    public function approve(string $accountId, array $grantedScopes): self
    {
        return new self($this->deviceCodeHash, $this->userCode, $this->clientId, $this->requestedScopes, $this->expiresAt, $this->interval, DeviceStatus::Approved, $accountId, $grantedScopes, $this->lastPolledAt);
    }

    public function withStatus(DeviceStatus $status): self
    {
        return new self($this->deviceCodeHash, $this->userCode, $this->clientId, $this->requestedScopes, $this->expiresAt, $this->interval, $status, $this->accountId, $this->grantedScopes, $this->lastPolledAt);
    }

    public function polled(\DateTimeImmutable $at, int $interval): self
    {
        return new self($this->deviceCodeHash, $this->userCode, $this->clientId, $this->requestedScopes, $this->expiresAt, $interval, $this->status, $this->accountId, $this->grantedScopes, $at);
    }
}
