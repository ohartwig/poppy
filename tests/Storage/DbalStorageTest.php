<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Koh\Poppy\Feedback\FeedbackReport;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Resource\SessionContext;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Storage\Dbal\DbalFeedbackSink;
use Koh\Poppy\Storage\Dbal\DbalReplayGuard;
use Koh\Poppy\Storage\Dbal\DbalStorage;
use Koh\Poppy\Storage\Dbal\PoppySchema;
use Koh\Poppy\Tests\Support\FrozenClock;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\TestCase;

/** The DBAL storage under the real protocol flows, on SQLite. */
final class DbalStorageTest extends TestCase
{
    private const PREFIX = 'test_poppy_';

    private Connection $connection;

    private FrozenClock $clock;

    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        PoppySchema::addTo($schema, self::PREFIX);
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
        }

        $this->clock = new FrozenClock();
        $this->company = new TestCompany(
            storage: new DbalStorage($this->connection, self::PREFIX),
            replayGuard: new DbalReplayGuard($this->connection, $this->clock, self::PREFIX),
            clock: $this->clock,
        );
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testTheSchemaHasEveryTable(): void
    {
        $tables = $this->connection->createSchemaManager()->listTableNames();
        sort($tables);
        $expected = PoppySchema::tableNames(self::PREFIX);
        sort($expected);

        self::assertSame($expected, $tables);
    }

    public function testSignInRenewalAndSignOutRoundTripThroughTheDatabase(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');

        $verifier = Base64Url::encode(random_bytes(32));
        $signIn = $this->company->server->directSignIn();
        $redirect = $signIn->approve($signIn->validate([
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read poppy:write',
            'code_challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]), 'account-A', ['poppy:read', 'poppy:write']);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        $exchange = fn () => TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => is_string($query['code'] ?? null) ? $query['code'] : '',
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => $session,
        ]));

        $tokens = $exchange();
        self::assertTrue($tokens['signed_in']);
        self::assertSame('poppy:read poppy:write', $tokens['scope']);
        self::assertSame('invalid_grant', $exchange()['error'], 'the code is gone');

        $stored = $this->company->storage->findSession($session);
        self::assertNotNull($stored);
        self::assertSame('account-A', $stored->accountId);
        self::assertSame(['poppy:read', 'poppy:write'], $stored->scopes);

        $accountToken = TestCompany::text($tokens, 'refresh_token');
        $record = $this->company->storage->findAccountTokenByHash(hash('sha256', $accountToken));
        self::assertNotNull($record);
        self::assertEquals($record, $this->company->storage->findAccountToken($record->id), 'found by id as well');
        self::assertCount(1, $this->company->storage->findAccountTokensForAccount('account-A'));

        $sessionToken = $this->company->storage->findSessionTokenByHash(hash('sha256', TestCompany::text($tokens, 'access_token')));
        self::assertNotNull($sessionToken);
        self::assertSame($record->id, $sessionToken->accountTokenId);
        self::assertNotNull($sessionToken->jkt);

        $this->company->server->disconnector()->revoke($record);
        $signedOut = $this->company->storage->findSession($session);
        self::assertNotNull($signedOut);
        self::assertFalse($signedOut->isSignedIn());
        self::assertSame('account-A', $signedOut->accountId);
        self::assertSame([], $this->company->server->disconnector()->connections('account-A'));
    }

    public function testReplayedAssertionsAreRefusedThroughTheDatabase(): void
    {
        $assertion = $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->clock->now());
        $parameters = ['grant_type' => TokenEndpoint::GRANT_JWT_BEARER, 'assertion' => $assertion];

        self::assertSame(200, $this->company->token($this->agent, $parameters)->getStatusCode());
        self::assertSame('invalid_grant', TestCompany::json($this->company->token($this->agent, $parameters))['error']);
    }

    public function testTheReplayGuardTakesOverOnlyExpiredIds(): void
    {
        $guard = new DbalReplayGuard($this->connection, $this->clock, self::PREFIX);
        $soon = $this->clock->now()->modify('+60 seconds');

        self::assertTrue($guard->claim('scope', 'id', $soon));
        self::assertFalse($guard->claim('scope', 'id', $soon));
        self::assertTrue($guard->claim('other-scope', 'id', $soon));

        $this->clock->advance(61);
        self::assertTrue($guard->claim('scope', 'id', $this->clock->now()->modify('+60 seconds')), 'an expired id may be used again');
        self::assertFalse($guard->claim('scope', 'id', $soon));

        $guard->purgeExpired($this->clock->now()->modify('+1 day'));
        self::assertEquals(0, $this->connection->fetchOne('SELECT COUNT(*) FROM ' . self::PREFIX . 'replay'));
    }

    public function testCodesAndDeviceApprovalsAreHandedOutOnce(): void
    {
        $storage = new DbalStorage($this->connection, self::PREFIX);
        $expires = $this->clock->now()->modify('+60 seconds');

        $storage->saveAuthorizationCode(new AuthorizationCode('h1', 'c', 'https://a.example/cb', 'ch', 'acc', ['poppy:read'], $expires));
        $code = $storage->consumeAuthorizationCode('h1');
        self::assertNotNull($code);
        self::assertSame(['poppy:read'], $code->scopes);
        self::assertSame('https://a.example/cb', $code->redirectUri);
        self::assertNull($storage->consumeAuthorizationCode('h1'));

        $device = new DeviceAuthorization('d1', 'BCDF-GHJK', 'c', ['poppy:read'], $expires, 5);
        $storage->saveDeviceAuthorization($device);
        self::assertNull($storage->consumeApprovedDeviceAuthorization('d1'), 'pending is not approved');

        $storage->saveDeviceAuthorization($device->polled($this->clock->now(), 10));
        $storage->saveDeviceAuthorization($device->approve('acc', ['poppy:read']));
        self::assertSame('d1', $storage->findDeviceAuthorizationByUserCode('BCDF-GHJK')?->deviceCodeHash);

        $taken = $storage->consumeApprovedDeviceAuthorization('d1');
        self::assertNotNull($taken);
        self::assertSame('acc', $taken->accountId);
        self::assertSame(['poppy:read'], $taken->grantedScopes);
        self::assertNull($storage->consumeApprovedDeviceAuthorization('d1'));
        self::assertSame(DeviceStatus::Consumed, $storage->findDeviceAuthorization('d1')?->status);
    }

    public function testPurgeRemovesExpiredRecordsOnly(): void
    {
        $storage = new DbalStorage($this->connection, self::PREFIX);
        $now = $this->clock->now();
        $storage->saveSession(new Session('old', 'c', 'u', $now, $now->modify('+1 second')));
        $storage->saveSession(new Session('new', 'c', 'u', $now, $now->modify('+1 day')));

        $storage->purgeExpired($now->modify('+1 hour'));

        self::assertNull($storage->findSession('old'));
        self::assertNotNull($storage->findSession('new'));
    }

    public function testFeedbackIsStoredAndReadBack(): void
    {
        $sink = new DbalFeedbackSink($this->connection, self::PREFIX);
        $context = new SessionContext('ses_1', 'https://agent.example/agent.json', 'usr_1', null, []);

        $sink->record(FeedbackReport::fromJson('{"kind":"missing","task":"Gift card","description":"No field."}'), $context, $this->clock->now());
        $sink->record(FeedbackReport::fromJson('{"kind":"missing","task":"Second","description":"Later."}'), $context, $this->clock->now()->modify('+1 minute'));

        $latest = $sink->latest(10);
        self::assertCount(2, $latest);
        self::assertSame('Second', $latest[0]['task']);
        self::assertSame('https://agent.example/agent.json', $latest[1]['client_id']);
        self::assertFalse($latest[1]['signed_in']);
        self::assertSame($this->clock->now()->getTimestamp(), $latest[1]['received_at']->getTimestamp());
        self::assertCount(1, $sink->latest(1));
    }
}
