<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Storage\InMemoryStorage;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Storage\Dbal\DbalStorage;
use Koh\Poppy\Storage\Dbal\PoppySchema;
use Koh\Poppy\Tests\Support\InterleavingStorage;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A Session is written by more than one request: a refresh, a sign-in and a
 * sign-out can meet on it. None of them may write back what it read earlier,
 * and a Session whose Account Token is gone must not get stuck. Every case
 * runs on both storages.
 */
final class SessionSignInRaceTest extends TestCase
{
    private const USER = 'usr_Q7c1vK';

    private InterleavingStorage $storage;

    private TestCompany $company;

    private PersonalAgent $agent;

    /** @return iterable<string, array{\Closure(): PoppyStorage}> */
    public static function storages(): iterable
    {
        yield 'in memory' => [static fn (): PoppyStorage => new InMemoryStorage()];
        yield 'dbal' => [static function (): PoppyStorage {
            $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
            $schema = new Schema();
            PoppySchema::addTo($schema, 'race_');
            foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
                $connection->executeStatement($sql);
            }

            return new DbalStorage($connection, 'race_');
        }];
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testARefreshDoesNotUndoASignOutGivenBetweenItsReadAndItsWrite(\Closure $storage): void
    {
        $this->start($storage);
        $session = $this->newSession();
        $accountToken = $this->signIn($session, 'account-A');
        $record = $this->company->storage->findAccountTokenByHash(hash('sha256', $accountToken));
        self::assertNotNull($record);

        $this->storage->afterNextSessionRead(fn () => $this->company->server->disconnector()->revoke($record));
        $refresh = $this->refresh($accountToken, $session);

        self::assertSame('invalid_grant', $refresh['error'], 'the token was revoked while this request ran');
        $stored = $this->company->storage->findSession($session);
        self::assertNotNull($stored);
        self::assertFalse($stored->isSignedIn(), 'the sign-out stands');
        self::assertSame([], $stored->scopes);
        self::assertSame('account-A', $stored->accountId);
        self::assertFalse($this->renew($session)['signed_in'], 'and the Session continues signed out');
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testTwoRefreshesCannotPutOneSessionOnTwoAccounts(\Closure $storage): void
    {
        $this->start($storage);
        $tokenA = $this->signIn($this->newSession(), 'account-A');
        $tokenB = $this->signIn($this->newSession(), 'account-B');
        $fresh = $this->newSession();

        $concurrent = null;
        $this->storage->afterNextSessionRead(function () use (&$concurrent, $tokenB, $fresh): void {
            $concurrent = $this->refresh($tokenB, $fresh);
        });
        $refresh = $this->refresh($tokenA, $fresh);

        self::assertIsArray($concurrent);
        self::assertTrue($concurrent['signed_in'], 'the request that wrote first signed the Session in');
        self::assertSame('account_mismatch', $refresh['error'], 'the other one read a Session without an account, but may not switch it');
        self::assertSame('account-B', $this->company->storage->findSession($fresh)?->accountId);
        self::assertSame('account_mismatch', $this->refresh($tokenA, $fresh)['error']);
        self::assertTrue($this->refresh($tokenB, $fresh)['signed_in']);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testASignInThatLosesTheSessionLeavesNoUsableAccountToken(\Closure $storage): void
    {
        $this->start($storage);
        $tokenB = $this->signIn($this->newSession(), 'account-B');
        $fresh = $this->newSession();
        [$code, $verifier] = $this->code('account-A');

        $this->storage->afterNextSessionRead(function () use ($tokenB, $fresh): void {
            self::assertTrue($this->refresh($tokenB, $fresh)['signed_in']);
        });
        $exchange = $this->exchange($code, $verifier, $fresh);

        self::assertSame('account_mismatch', $exchange['error']);
        self::assertArrayNotHasKey('refresh_token', $exchange);
        self::assertSame([], $this->company->server->disconnector()->connections('account-A'), 'the token issued for account A was revoked again');
        self::assertSame('account-B', $this->company->storage->findSession($fresh)?->accountId);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testASessionWhoseAccountTokenExpiredContinuesSignedOut(\Closure $storage): void
    {
        $this->start($storage);
        $accountToken = $this->signIn($this->newSession(), 'account-A');

        // Day 89 of the token's 90: it starts a Session that lives 30 days.
        $this->company->clock->advance(89 * 86400);
        $late = $this->refresh($accountToken, null);
        self::assertTrue($late['signed_in']);
        $session = TestCompany::text($late, 'session_id');
        self::assertSame('invalid_grant', $this->renew($session)['error'], 'while the token is usable, the Session is renewed with it');
        self::assertTrue($this->company->storage->findSession($session)?->isSignedIn());

        $this->company->clock->advance(2 * 86400);
        self::assertSame('invalid_grant', $this->refresh($accountToken, $session)['error'], 'the token has expired');

        $renewed = $this->renew($session);
        self::assertFalse($renewed['signed_in']);
        self::assertSame($session, $renewed['session_id']);
        $stored = $this->company->storage->findSession($session);
        self::assertNotNull($stored);
        self::assertFalse($stored->isSignedIn());
        self::assertSame('account-A', $stored->accountId, 'still bound to its account');
        self::assertFalse($this->renew($session)['signed_in'], 'and renews again');
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testASessionWhoseAccountTokenWasPurgedContinuesSignedOut(\Closure $storage): void
    {
        $this->start($storage);
        $accountToken = $this->signIn($this->newSession(), 'account-A');
        $this->company->clock->advance(89 * 86400);
        $session = TestCompany::text($this->refresh($accountToken, null), 'session_id');

        $this->company->clock->advance(2 * 86400);
        $this->company->storage->purgeExpired($this->company->clock->now());
        self::assertNull($this->company->storage->findAccountTokenByHash(hash('sha256', $accountToken)));

        self::assertFalse($this->renew($session)['signed_in']);
        self::assertFalse($this->company->storage->findSession($session)?->isSignedIn());
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testDisconnectingWithdrawsApprovedSignInsThatWereNotExchanged(\Closure $storage): void
    {
        $this->start($storage);
        $session = $this->newSession();
        $this->signIn($session, 'account-A');
        $other = $this->newSession();

        [$code, $verifier] = $this->code('account-A');
        $deviceCode = TestCompany::text(TestCompany::json($this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        ))), 'device_code');
        $pending = $this->company->storage->findDeviceAuthorization(hash('sha256', $deviceCode));
        self::assertNotNull($pending);
        self::assertTrue($this->company->server->deviceVerification()->approve($pending, 'account-A', ['poppy:read']));

        $this->company->server->disconnector()->disconnect('account-A', $this->agent->clientId);

        self::assertSame('invalid_grant', $this->exchange($code, $verifier, $other)['error'], 'the code approved before the disconnect is gone');
        self::assertSame('access_denied', TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_DEVICE_CODE,
            'device_code' => $deviceCode,
            'session_id' => $other,
        ]))['error']);
        self::assertSame([], $this->company->server->disconnector()->connections('account-A'));
        self::assertFalse($this->company->storage->findSession($session)?->isSignedIn());
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testCancellingTouchesOnlyThatAgentOnThatAccount(\Closure $storage): void
    {
        $inner = $storage();
        $expires = new \DateTimeImmutable('2030-01-01 00:00:00 UTC');
        $device = static fn (string $hash, string $client, DeviceStatus $status, ?string $account): DeviceAuthorization => new DeviceAuthorization($hash, 'CODE-' . $hash, $client, ['poppy:read'], $expires, 5, $status, $account, $account !== null ? ['poppy:read'] : []);

        foreach ([['hit', 'agent', 'acc'], ['other-agent', 'other', 'acc'], ['other-account', 'agent', 'other']] as [$hash, $client, $account]) {
            $inner->saveAuthorizationCode(new AuthorizationCode($hash, $client, 'https://a.example/cb', 'ch', $account, ['poppy:read'], $expires));
            $inner->saveDeviceAuthorization($device('device-' . $hash, $client, DeviceStatus::Approved, $account));
        }
        $inner->saveDeviceAuthorization($device('pending', 'agent', DeviceStatus::Pending, null));
        $inner->saveDeviceAuthorization($device('consumed', 'agent', DeviceStatus::Consumed, 'acc'));

        $inner->cancelApprovedSignIns('acc', 'agent');

        self::assertNull($inner->consumeAuthorizationCode('hit'));
        self::assertNotNull($inner->consumeAuthorizationCode('other-agent'));
        self::assertNotNull($inner->consumeAuthorizationCode('other-account'));
        self::assertSame(DeviceStatus::Denied, $inner->findDeviceAuthorization('device-hit')?->status);
        self::assertSame(DeviceStatus::Approved, $inner->findDeviceAuthorization('device-other-agent')?->status);
        self::assertSame(DeviceStatus::Approved, $inner->findDeviceAuthorization('device-other-account')?->status);
        self::assertSame(DeviceStatus::Pending, $inner->findDeviceAuthorization('pending')?->status);
        self::assertSame(DeviceStatus::Consumed, $inner->findDeviceAuthorization('consumed')?->status, 'a used device code stays used');
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testSigningASessionInIsConditional(\Closure $storage): void
    {
        $inner = $storage();
        $now = new \DateTimeImmutable('2026-10-27 12:00:00 UTC');
        $token = static fn (string $id, string $account): AccountToken => new AccountToken($id, 'hash-' . $id, 'agent', 'usr', $account, ['poppy:read'], $now);
        $inner->saveSession(new Session('ses', 'agent', 'usr', $now, $now->modify('+1 day')));
        $inner->saveSession(new Session('bystander', 'agent', 'usr', $now, $now->modify('+1 day')));

        self::assertFalse($inner->signInSession('unknown', $token('t1', 'acc-A'), ['poppy:read']));

        self::assertTrue($inner->signInSession('ses', $token('t1', 'acc-A'), ['poppy:read', 'poppy:write']));
        self::assertEquals(new Session('ses', 'agent', 'usr', $now, $now->modify('+1 day'), 'acc-A', 't1', ['poppy:read', 'poppy:write']), $inner->findSession('ses'));
        self::assertTrue($inner->signInSession('ses', $token('t1', 'acc-A'), ['poppy:read', 'poppy:write']), 'the same sign-in again is not a failure');

        self::assertFalse($inner->signInSession('ses', $token('t2', 'acc-B'), ['poppy:read']), 'never to another account');
        self::assertFalse($inner->signInSession('ses', $token('t2', 'acc-B'), ['poppy:read', 'poppy:write']), 'nor with the scopes it already has');
        self::assertEquals(new Session('ses', 'agent', 'usr', $now, $now->modify('+1 day'), 'acc-A', 't1', ['poppy:read', 'poppy:write']), $inner->findSession('ses'), 'and nothing was written');

        $inner->signOutSessions('t1');
        self::assertFalse($inner->signInSession('ses', $token('t2', 'acc-B'), ['poppy:read']), 'not after a sign-out either');
        self::assertTrue($inner->signInSession('ses', $token('t3', 'acc-A'), ['poppy:read']), 'the same account, under a new token');
        self::assertEquals(new Session('ses', 'agent', 'usr', $now, $now->modify('+1 day'), 'acc-A', 't3', ['poppy:read']), $inner->findSession('ses'));

        self::assertEquals(new Session('bystander', 'agent', 'usr', $now, $now->modify('+1 day')), $inner->findSession('bystander'));
    }

    /** @param \Closure(): PoppyStorage $storage */
    private function start(\Closure $storage): void
    {
        $this->storage = new InterleavingStorage($storage());
        $this->company = new TestCompany(storage: $this->storage);
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    private function newSession(): string
    {
        return TestCompany::text($this->company->startSession($this->agent, self::USER), 'session_id');
    }

    /** @return array<string, mixed> */
    private function renew(string $session): array
    {
        return TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, self::USER, $this->company->clock->now()),
            'session_id' => $session,
        ]));
    }

    /** @return array<string, mixed> */
    private function refresh(string $accountToken, ?string $session): array
    {
        return TestCompany::json($this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountToken] + ($session !== null ? ['session_id' => $session] : [])));
    }

    /** @return array{string, string} the code and its verifier */
    private function code(string $account): array
    {
        $verifier = Base64Url::encode(random_bytes(32));
        $signIn = $this->company->server->directSignIn();
        $redirect = $signIn->approve($signIn->validate([
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read',
            'code_challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]), $account, ['poppy:read']);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        self::assertIsString($query['code'] ?? null);

        return [$query['code'], $verifier];
    }

    /** @return array<string, mixed> */
    private function exchange(string $code, string $verifier, string $session): array
    {
        return TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => $session,
        ]));
    }

    private function signIn(string $session, string $account): string
    {
        [$code, $verifier] = $this->code($account);

        return TestCompany::text($this->exchange($code, $verifier, $session), 'refresh_token');
    }
}
