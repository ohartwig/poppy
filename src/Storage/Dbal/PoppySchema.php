<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Storage\Dbal;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Types\Types;

/**
 * The tables behind DbalStorage, DbalReplayGuard and DbalFeedbackSink.
 *
 * Times are Unix timestamps in integer columns: the same on every platform,
 * comparable in SQL without a timezone, and free of the datetime-type
 * differences between DBAL 3 and 4. Token columns hold SHA-256 hex digests,
 * never tokens.
 *
 * Integrations put these tables into their own schema management — a
 * Doctrine migration in Sylius, ext_tables.sql in TYPO3 — so the names carry
 * a prefix the integration chooses.
 */
final class PoppySchema
{
    public static function addTo(Schema $schema, string $prefix): void
    {
        $session = $schema->createTable($prefix . 'session');
        $session->addColumn('id', Types::STRING, ['length' => 64]);
        $session->addColumn('client_id', Types::STRING, ['length' => 512]);
        $session->addColumn('user_id', Types::STRING, ['length' => 255]);
        $session->addColumn('account_id', Types::STRING, ['length' => 191, 'notnull' => false]);
        $session->addColumn('account_token_id', Types::STRING, ['length' => 64, 'notnull' => false]);
        $session->addColumn('scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $session->addColumn('created_at', Types::INTEGER);
        $session->addColumn('expires_at', Types::INTEGER);
        $session->setPrimaryKey(['id']);
        $session->addIndex(['account_token_id'], $prefix . 'session_account_token');
        $session->addIndex(['expires_at'], $prefix . 'session_expires');

        $accountToken = $schema->createTable($prefix . 'account_token');
        $accountToken->addColumn('id', Types::STRING, ['length' => 64]);
        $accountToken->addColumn('hash', Types::STRING, ['length' => 64, 'fixed' => true]);
        $accountToken->addColumn('client_id', Types::STRING, ['length' => 512]);
        $accountToken->addColumn('user_id', Types::STRING, ['length' => 255]);
        $accountToken->addColumn('account_id', Types::STRING, ['length' => 191]);
        $accountToken->addColumn('scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $accountToken->addColumn('issued_at', Types::INTEGER);
        $accountToken->addColumn('expires_at', Types::INTEGER, ['notnull' => false]);
        $accountToken->addColumn('revoked_at', Types::INTEGER, ['notnull' => false]);
        $accountToken->setPrimaryKey(['id']);
        $accountToken->addUniqueIndex(['hash'], $prefix . 'account_token_hash');
        $accountToken->addIndex(['account_id'], $prefix . 'account_token_account');

        $sessionToken = $schema->createTable($prefix . 'session_token');
        $sessionToken->addColumn('hash', Types::STRING, ['length' => 64, 'fixed' => true]);
        $sessionToken->addColumn('session_id', Types::STRING, ['length' => 64]);
        $sessionToken->addColumn('client_id', Types::STRING, ['length' => 512]);
        $sessionToken->addColumn('user_id', Types::STRING, ['length' => 255]);
        $sessionToken->addColumn('type', Types::STRING, ['length' => 8]);
        $sessionToken->addColumn('jkt', Types::STRING, ['length' => 64, 'notnull' => false]);
        $sessionToken->addColumn('resource', Types::STRING, ['length' => 512, 'notnull' => false]);
        $sessionToken->addColumn('scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $sessionToken->addColumn('account_token_id', Types::STRING, ['length' => 64, 'notnull' => false]);
        $sessionToken->addColumn('issued_at', Types::INTEGER);
        $sessionToken->addColumn('expires_at', Types::INTEGER);
        $sessionToken->setPrimaryKey(['hash']);
        $sessionToken->addIndex(['expires_at'], $prefix . 'session_token_expires');

        $code = $schema->createTable($prefix . 'authorization_code');
        $code->addColumn('hash', Types::STRING, ['length' => 64, 'fixed' => true]);
        $code->addColumn('client_id', Types::STRING, ['length' => 512]);
        $code->addColumn('redirect_uri', Types::STRING, ['length' => 2048]);
        $code->addColumn('code_challenge', Types::STRING, ['length' => 64]);
        $code->addColumn('account_id', Types::STRING, ['length' => 191]);
        $code->addColumn('scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $code->addColumn('expires_at', Types::INTEGER);
        $code->setPrimaryKey(['hash']);

        $device = $schema->createTable($prefix . 'device_authorization');
        $device->addColumn('device_code_hash', Types::STRING, ['length' => 64, 'fixed' => true]);
        $device->addColumn('user_code', Types::STRING, ['length' => 9]);
        $device->addColumn('client_id', Types::STRING, ['length' => 512]);
        $device->addColumn('requested_scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $device->addColumn('granted_scopes', Types::STRING, ['length' => 1024, 'default' => '']);
        $device->addColumn('status', Types::STRING, ['length' => 16]);
        $device->addColumn('account_id', Types::STRING, ['length' => 191, 'notnull' => false]);
        $device->addColumn('expires_at', Types::INTEGER);
        $device->addColumn('interval_seconds', Types::INTEGER);
        $device->addColumn('last_polled_at', Types::INTEGER, ['notnull' => false]);
        $device->setPrimaryKey(['device_code_hash']);
        $device->addIndex(['user_code'], $prefix . 'device_user_code');

        // One row per one-time id. The key is a hash of scope and id, so the
        // primary key stays short enough for every engine's index limit.
        $replay = $schema->createTable($prefix . 'replay');
        $replay->addColumn('id_hash', Types::STRING, ['length' => 64, 'fixed' => true]);
        $replay->addColumn('expires_at', Types::INTEGER);
        $replay->setPrimaryKey(['id_hash']);
        $replay->addIndex(['expires_at'], $prefix . 'replay_expires');

        $feedback = $schema->createTable($prefix . 'feedback');
        $feedback->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
        $feedback->addColumn('client_id', Types::STRING, ['length' => 512]);
        $feedback->addColumn('user_id', Types::STRING, ['length' => 255]);
        $feedback->addColumn('session_id', Types::STRING, ['length' => 64]);
        $feedback->addColumn('signed_in', Types::BOOLEAN, ['default' => false]);
        $feedback->addColumn('kind', Types::STRING, ['length' => 64]);
        $feedback->addColumn('task', Types::STRING, ['length' => 255]);
        $feedback->addColumn('description', Types::TEXT);
        $feedback->addColumn('received_at', Types::INTEGER);
        $feedback->setPrimaryKey(['id']);
        $feedback->addIndex(['received_at'], $prefix . 'feedback_received');
    }

    /** @return list<string> */
    public static function tableNames(string $prefix): array
    {
        return array_map(
            static fn (string $name): string => $prefix . $name,
            ['session', 'account_token', 'session_token', 'authorization_code', 'device_authorization', 'replay', 'feedback'],
        );
    }
}
