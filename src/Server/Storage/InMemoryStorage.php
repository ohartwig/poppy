<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Storage;

use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\SessionToken;

/**
 * Reference implementation in memory: for tests, and as a readable statement
 * of what each storage method has to do. Single process only.
 */
final class InMemoryStorage implements PoppyStorage
{
    /** @var array<string, Session> */
    private array $sessions = [];

    /** @var array<string, AccountToken> keyed by id */
    private array $accountTokens = [];

    /** @var array<string, SessionToken> keyed by hash */
    private array $sessionTokens = [];

    /** @var array<string, AuthorizationCode> keyed by hash */
    private array $codes = [];

    /** @var array<string, DeviceAuthorization> keyed by device code hash */
    private array $devices = [];

    public function saveSession(Session $session): void
    {
        $this->sessions[$session->id] = $session;
    }

    public function findSession(string $id): ?Session
    {
        return $this->sessions[$id] ?? null;
    }

    public function signOutSessions(string $accountTokenId): void
    {
        foreach ($this->sessions as $id => $session) {
            if ($session->accountTokenId === $accountTokenId) {
                $this->sessions[$id] = $session->signOut();
            }
        }
    }

    public function saveAccountToken(AccountToken $token): void
    {
        $this->accountTokens[$token->id] = $token;
    }

    public function findAccountTokenByHash(string $hash): ?AccountToken
    {
        foreach ($this->accountTokens as $token) {
            if (hash_equals($token->hash, $hash)) {
                return $token;
            }
        }

        return null;
    }

    public function findAccountToken(string $id): ?AccountToken
    {
        return $this->accountTokens[$id] ?? null;
    }

    public function findAccountTokensForAccount(string $accountId): array
    {
        return array_values(array_filter($this->accountTokens, static fn (AccountToken $token): bool => $token->accountId === $accountId));
    }

    public function saveSessionToken(SessionToken $token): void
    {
        $this->sessionTokens[$token->hash] = $token;
    }

    public function findSessionTokenByHash(string $hash): ?SessionToken
    {
        return $this->sessionTokens[$hash] ?? null;
    }

    public function saveAuthorizationCode(AuthorizationCode $code): void
    {
        $this->codes[$code->hash] = $code;
    }

    public function consumeAuthorizationCode(string $hash): ?AuthorizationCode
    {
        $code = $this->codes[$hash] ?? null;
        unset($this->codes[$hash]);

        return $code;
    }

    public function saveDeviceAuthorization(DeviceAuthorization $authorization): void
    {
        $this->devices[$authorization->deviceCodeHash] = $authorization;
    }

    public function findDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        return $this->devices[$deviceCodeHash] ?? null;
    }

    public function findDeviceAuthorizationByUserCode(string $userCode): ?DeviceAuthorization
    {
        foreach ($this->devices as $authorization) {
            if ($authorization->userCode === $userCode) {
                return $authorization;
            }
        }

        return null;
    }

    public function consumeApprovedDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        $authorization = $this->devices[$deviceCodeHash] ?? null;
        if ($authorization === null || $authorization->status !== DeviceStatus::Approved) {
            return null;
        }

        $this->devices[$deviceCodeHash] = $authorization->withStatus(DeviceStatus::Consumed);

        return $authorization;
    }

    public function purgeExpired(\DateTimeImmutable $now): void
    {
        $this->sessions = array_filter($this->sessions, static fn (Session $session): bool => $session->isActive($now));
        $this->sessionTokens = array_filter($this->sessionTokens, static fn (SessionToken $token): bool => !$token->isExpired($now));
        $this->codes = array_filter($this->codes, static fn (AuthorizationCode $code): bool => $now < $code->expiresAt);
        $this->devices = array_filter($this->devices, static fn (DeviceAuthorization $device): bool => !$device->isExpired($now));
        $this->accountTokens = array_filter($this->accountTokens, static fn (AccountToken $token): bool => $token->isUsable($now));
    }
}
