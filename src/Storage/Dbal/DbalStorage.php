<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Storage\Dbal;

use Doctrine\DBAL\Connection;
use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\SessionToken;
use Koh\Poppy\Server\Model\TokenType;
use Koh\Poppy\Server\Storage\PoppyStorage;

/**
 * PoppyStorage on Doctrine DBAL 3.10 or 4, for every integration.
 *
 * The two single-use operations are made atomic by the database: a code is
 * taken by the DELETE that removes it, a device authorization by the UPDATE
 * whose WHERE clause still expects "approved". Whichever request's statement
 * affects the row wins; the other sees zero affected rows and gets nothing.
 *
 * "Save" is an upsert done as UPDATE-then-INSERT. That is not atomic, and does
 * not need to be: every record is written by the one request that owns it,
 * and the races that matter are the two above.
 */
final readonly class DbalStorage implements PoppyStorage
{
    public function __construct(
        private Connection $connection,
        private string $prefix = 'koh_poppy_',
    ) {}

    public function saveSession(Session $session): void
    {
        $this->upsert('session', ['id' => $session->id], [
            'client_id' => $session->clientId,
            'user_id' => $session->userId,
            'account_id' => $session->accountId,
            'account_token_id' => $session->accountTokenId,
            'scopes' => implode(' ', $session->scopes),
            'created_at' => $session->createdAt->getTimestamp(),
            'expires_at' => $session->expiresAt->getTimestamp(),
        ]);
    }

    public function findSession(string $id): ?Session
    {
        $row = $this->row('session', ['id' => $id]);

        return $row === null ? null : new Session(
            self::string($row, 'id'),
            self::string($row, 'client_id'),
            self::string($row, 'user_id'),
            self::time($row, 'created_at'),
            self::time($row, 'expires_at'),
            self::nullableString($row, 'account_id'),
            self::nullableString($row, 'account_token_id'),
            self::scopes($row, 'scopes'),
        );
    }

    public function signOutSessions(string $accountTokenId): void
    {
        $this->connection->update(
            $this->prefix . 'session',
            ['account_token_id' => null, 'scopes' => ''],
            ['account_token_id' => $accountTokenId],
        );
    }

    public function saveAccountToken(AccountToken $token): void
    {
        $this->upsert('account_token', ['id' => $token->id], [
            'hash' => $token->hash,
            'client_id' => $token->clientId,
            'user_id' => $token->userId,
            'account_id' => $token->accountId,
            'scopes' => implode(' ', $token->scopes),
            'issued_at' => $token->issuedAt->getTimestamp(),
            'expires_at' => $token->expiresAt?->getTimestamp(),
            'revoked_at' => $token->revokedAt?->getTimestamp(),
        ]);
    }

    public function findAccountTokenByHash(string $hash): ?AccountToken
    {
        $row = $this->row('account_token', ['hash' => $hash]);

        return $row === null ? null : self::accountToken($row);
    }

    public function findAccountToken(string $id): ?AccountToken
    {
        $row = $this->row('account_token', ['id' => $id]);

        return $row === null ? null : self::accountToken($row);
    }

    public function findAccountTokensForAccount(string $accountId): array
    {
        $rows = $this->connection->createQueryBuilder()
            ->select('*')
            ->from($this->prefix . 'account_token')
            ->where('account_id = :account')
            ->orderBy('issued_at', 'DESC')
            ->setParameter('account', $accountId)
            ->executeQuery()
            ->fetchAllAssociative();

        return array_map(self::accountToken(...), $rows);
    }

    public function saveSessionToken(SessionToken $token): void
    {
        $this->connection->insert($this->prefix . 'session_token', [
            'hash' => $token->hash,
            'session_id' => $token->sessionId,
            'client_id' => $token->clientId,
            'user_id' => $token->userId,
            'type' => $token->type->value,
            'jkt' => $token->jkt,
            'resource' => $token->resource,
            'scopes' => implode(' ', $token->scopes),
            'account_token_id' => $token->accountTokenId,
            'issued_at' => $token->issuedAt->getTimestamp(),
            'expires_at' => $token->expiresAt->getTimestamp(),
        ]);
    }

    public function findSessionTokenByHash(string $hash): ?SessionToken
    {
        $row = $this->row('session_token', ['hash' => $hash]);

        return $row === null ? null : new SessionToken(
            self::string($row, 'hash'),
            self::string($row, 'session_id'),
            self::string($row, 'client_id'),
            self::string($row, 'user_id'),
            TokenType::from(self::string($row, 'type')),
            self::nullableString($row, 'jkt'),
            self::nullableString($row, 'resource'),
            self::scopes($row, 'scopes'),
            self::nullableString($row, 'account_token_id'),
            self::time($row, 'issued_at'),
            self::time($row, 'expires_at'),
        );
    }

    public function saveAuthorizationCode(AuthorizationCode $code): void
    {
        $this->connection->insert($this->prefix . 'authorization_code', [
            'hash' => $code->hash,
            'client_id' => $code->clientId,
            'redirect_uri' => $code->redirectUri,
            'code_challenge' => $code->codeChallenge,
            'account_id' => $code->accountId,
            'scopes' => implode(' ', $code->scopes),
            'expires_at' => $code->expiresAt->getTimestamp(),
        ]);
    }

    public function consumeAuthorizationCode(string $hash): ?AuthorizationCode
    {
        $row = $this->row('authorization_code', ['hash' => $hash]);
        if ($row === null || $this->connection->delete($this->prefix . 'authorization_code', ['hash' => $hash]) !== 1) {
            return null;
        }

        return new AuthorizationCode(
            self::string($row, 'hash'),
            self::string($row, 'client_id'),
            self::string($row, 'redirect_uri'),
            self::string($row, 'code_challenge'),
            self::string($row, 'account_id'),
            self::scopes($row, 'scopes'),
            self::time($row, 'expires_at'),
        );
    }

    public function saveDeviceAuthorization(DeviceAuthorization $authorization): void
    {
        $this->upsert('device_authorization', ['device_code_hash' => $authorization->deviceCodeHash], [
            'user_code' => $authorization->userCode,
            'client_id' => $authorization->clientId,
            'requested_scopes' => implode(' ', $authorization->requestedScopes),
            'granted_scopes' => implode(' ', $authorization->grantedScopes),
            'status' => $authorization->status->value,
            'account_id' => $authorization->accountId,
            'expires_at' => $authorization->expiresAt->getTimestamp(),
            'interval_seconds' => $authorization->interval,
            'last_polled_at' => $authorization->lastPolledAt?->getTimestamp(),
        ]);
    }

    public function findDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        $row = $this->row('device_authorization', ['device_code_hash' => $deviceCodeHash]);

        return $row === null ? null : self::deviceAuthorization($row);
    }

    public function findDeviceAuthorizationByUserCode(string $userCode): ?DeviceAuthorization
    {
        $row = $this->connection->createQueryBuilder()
            ->select('*')
            ->from($this->prefix . 'device_authorization')
            ->where('user_code = :code')
            ->orderBy('expires_at', 'DESC')
            ->setMaxResults(1)
            ->setParameter('code', $userCode)
            ->executeQuery()
            ->fetchAssociative();

        return $row === false ? null : self::deviceAuthorization($row);
    }

    public function consumeApprovedDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        $authorization = $this->findDeviceAuthorization($deviceCodeHash);
        if ($authorization === null || $authorization->status !== DeviceStatus::Approved) {
            return null;
        }

        $taken = $this->connection->update(
            $this->prefix . 'device_authorization',
            ['status' => DeviceStatus::Consumed->value],
            ['device_code_hash' => $deviceCodeHash, 'status' => DeviceStatus::Approved->value],
        );

        return $taken === 1 ? $authorization : null;
    }

    public function purgeExpired(\DateTimeImmutable $now): void
    {
        $time = $now->getTimestamp();
        foreach (['session', 'session_token', 'authorization_code', 'device_authorization'] as $table) {
            $this->connection->executeStatement(
                sprintf('DELETE FROM %s WHERE expires_at <= ?', $this->connection->quoteIdentifier($this->prefix . $table)),
                [$time],
            );
        }

        // Revoked Account Tokens are kept until they would have expired, so a
        // revoked token presented again is still recognised and refused as such.
        $this->connection->executeStatement(
            sprintf('DELETE FROM %s WHERE expires_at IS NOT NULL AND expires_at <= ?', $this->connection->quoteIdentifier($this->prefix . 'account_token')),
            [$time],
        );
    }

    /**
     * @param array<string, string>                      $key
     * @param array<string, string|int|null> $values
     */
    private function upsert(string $table, array $key, array $values): void
    {
        $updated = $this->connection->update($this->prefix . $table, $values, $key);
        if ($updated === 0 && $this->row($table, $key) === null) {
            $this->connection->insert($this->prefix . $table, $key + $values);
        }
    }

    /**
     * @param array<string, string> $key
     *
     * @return array<string, mixed>|null
     */
    private function row(string $table, array $key): ?array
    {
        $query = $this->connection->createQueryBuilder()->select('*')->from($this->prefix . $table)->setMaxResults(1);
        foreach ($key as $column => $value) {
            $query->andWhere($column . ' = :' . $column)->setParameter($column, $value);
        }

        $row = $query->executeQuery()->fetchAssociative();

        return $row === false ? null : $row;
    }

    /** @param array<string, mixed> $row */
    private static function accountToken(array $row): AccountToken
    {
        return new AccountToken(
            self::string($row, 'id'),
            self::string($row, 'hash'),
            self::string($row, 'client_id'),
            self::string($row, 'user_id'),
            self::string($row, 'account_id'),
            self::scopes($row, 'scopes'),
            self::time($row, 'issued_at'),
            self::nullableTime($row, 'expires_at'),
            self::nullableTime($row, 'revoked_at'),
        );
    }

    /** @param array<string, mixed> $row */
    private static function deviceAuthorization(array $row): DeviceAuthorization
    {
        return new DeviceAuthorization(
            self::string($row, 'device_code_hash'),
            self::string($row, 'user_code'),
            self::string($row, 'client_id'),
            self::scopes($row, 'requested_scopes'),
            self::time($row, 'expires_at'),
            (int) self::scalar($row, 'interval_seconds'),
            DeviceStatus::from(self::string($row, 'status')),
            self::nullableString($row, 'account_id'),
            self::scopes($row, 'granted_scopes'),
            self::nullableTime($row, 'last_polled_at'),
        );
    }

    /** @param array<string, mixed> $row */
    private static function string(array $row, string $column): string
    {
        return (string) self::scalar($row, $column);
    }

    /** @param array<string, mixed> $row */
    private static function nullableString(array $row, string $column): ?string
    {
        return $row[$column] === null ? null : self::string($row, $column);
    }

    /**
     * @param array<string, mixed> $row
     *
     * @return list<string>
     */
    private static function scopes(array $row, string $column): array
    {
        $value = self::string($row, $column);

        return $value === '' ? [] : explode(' ', $value);
    }

    /** @param array<string, mixed> $row */
    private static function time(array $row, string $column): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . (int) self::scalar($row, $column));
    }

    /** @param array<string, mixed> $row */
    private static function nullableTime(array $row, string $column): ?\DateTimeImmutable
    {
        return $row[$column] === null ? null : self::time($row, $column);
    }

    /** @param array<string, mixed> $row */
    private static function scalar(array $row, string $column): string|int|float|bool
    {
        $value = $row[$column] ?? null;
        if (!is_scalar($value)) {
            throw new \UnexpectedValueException(sprintf('Column %s is missing or not scalar.', $column));
        }

        return $value;
    }
}
