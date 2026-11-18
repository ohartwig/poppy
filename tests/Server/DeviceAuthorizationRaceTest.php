<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
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
 * A pending device authorization is written by two requests at once: the
 * Personal Agent's poll and the User's decision. Neither may write back what
 * it read earlier. Every case runs on both storages.
 */
final class DeviceAuthorizationRaceTest extends TestCase
{
    private InterleavingStorage $storage;

    private TestCompany $company;

    private PersonalAgent $agent;

    private string $session;

    private string $deviceCode;

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
    public function testAPollDoesNotUndoAnApprovalGivenBetweenItsReadAndItsWrite(\Closure $storage): void
    {
        $this->start($storage);
        $this->storage->afterNextDeviceRead(function (): void {
            self::assertTrue($this->company->server->deviceVerification()->approve($this->pending(), 'account-A', ['poppy:read']));
        });

        self::assertSame('authorization_pending', $this->poll()['error'], 'this poll read the record before the approval');

        $stored = $this->stored();
        self::assertSame(DeviceStatus::Approved, $stored->status);
        self::assertSame('account-A', $stored->accountId);
        self::assertSame(['poppy:read'], $stored->grantedScopes);
        self::assertNull($stored->lastPolledAt, 'the losing poll wrote nothing');

        $tokens = $this->poll();
        self::assertTrue($tokens['signed_in']);
        self::assertSame('poppy:read', $tokens['scope']);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testAPollDoesNotUndoADenialGivenBetweenItsReadAndItsWrite(\Closure $storage): void
    {
        $this->start($storage);
        $this->storage->afterNextDeviceRead(function (): void {
            self::assertTrue($this->company->server->deviceVerification()->deny($this->pending()));
        });

        self::assertSame('authorization_pending', $this->poll()['error']);
        self::assertSame('access_denied', $this->poll()['error']);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testASecondApprovalDoesNotReArmAUsedDeviceCode(\Closure $storage): void
    {
        $this->start($storage);
        $verification = $this->company->server->deviceVerification();
        $firstTab = $this->pending();
        $secondTab = $this->pending();

        self::assertTrue($verification->approve($firstTab, 'account-A', ['poppy:read']));
        self::assertTrue($this->poll()['signed_in']);

        self::assertFalse($verification->approve($secondTab, 'account-B', ['poppy:read']), 'the record is no longer pending');
        self::assertSame(DeviceStatus::Consumed, $this->stored()->status);
        self::assertSame('account-A', $this->stored()->accountId);
        self::assertSame('invalid_grant', $this->poll()['error'], 'the device code stays used');
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testTheFirstDecisionStands(\Closure $storage): void
    {
        $this->start($storage);
        $verification = $this->company->server->deviceVerification();
        $firstTab = $this->pending();
        $secondTab = $this->pending();

        self::assertTrue($verification->deny($firstTab));
        self::assertFalse($verification->approve($secondTab, 'account-A', ['poppy:read']));
        self::assertFalse($verification->deny($secondTab));
        self::assertSame(DeviceStatus::Denied, $this->stored()->status);
        self::assertNull($this->stored()->accountId);
        self::assertSame([], $this->stored()->grantedScopes);

        $this->start($storage);
        $verification = $this->company->server->deviceVerification();
        $firstTab = $this->pending();
        $secondTab = $this->pending();

        self::assertTrue($verification->approve($firstTab, 'account-A', ['poppy:read']));
        self::assertFalse($verification->deny($secondTab));
        self::assertFalse($verification->approve($secondTab, 'account-B', ['poppy:read']));
        self::assertSame(DeviceStatus::Approved, $this->stored()->status);
        self::assertSame('account-A', $this->stored()->accountId);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testADecisionLeavesThePollStateAlone(\Closure $storage): void
    {
        $this->start($storage);
        $beforeThePolls = $this->pending();
        self::assertSame(5, $beforeThePolls->interval);

        self::assertSame('authorization_pending', $this->poll()['error']);
        self::assertSame('slow_down', $this->poll()['error']);
        $polledAt = $this->company->clock->now();

        self::assertTrue($this->company->server->deviceVerification()->approve($beforeThePolls, 'account-A', ['poppy:read']));

        $stored = $this->stored();
        self::assertSame(10, $stored->interval, 'the approval did not reset the interval it read earlier');
        self::assertEquals($polledAt, $stored->lastPolledAt);
        self::assertSame($beforeThePolls->userCode, $stored->userCode);
        self::assertSame(['poppy:read'], $stored->requestedScopes);
        self::assertEquals($beforeThePolls->expiresAt, $stored->expiresAt);
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testTransitionsOfAnUnknownDeviceCodeDoNothing(\Closure $storage): void
    {
        $this->start($storage);
        $inner = $storage();

        $inner->recordDevicePoll('unknown', $this->company->clock->now(), 10);
        self::assertFalse($inner->approveDeviceAuthorization('unknown', 'account-A', ['poppy:read']));
        self::assertFalse($inner->denyDeviceAuthorization('unknown'));
        self::assertNull($inner->findDeviceAuthorization('unknown'));
    }

    /** @param \Closure(): PoppyStorage $storage */
    #[DataProvider('storages')]
    public function testATransitionTouchesOnlyItsOwnDeviceCode(\Closure $storage): void
    {
        $this->start($storage);
        $inner = $storage();
        $now = $this->company->clock->now();
        foreach (['polled', 'approved', 'denied', 'untouched'] as $hash) {
            $inner->saveDeviceAuthorization(new DeviceAuthorization($hash, 'CODE-' . $hash, 'c', ['poppy:read'], $now->modify('+10 minutes'), 5));
        }

        $inner->recordDevicePoll('polled', $now, 10);
        self::assertTrue($inner->approveDeviceAuthorization('approved', 'account-A', ['poppy:read']));
        self::assertTrue($inner->denyDeviceAuthorization('denied'));

        self::assertEquals(new DeviceAuthorization('polled', 'CODE-polled', 'c', ['poppy:read'], $now->modify('+10 minutes'), 10, lastPolledAt: $now), $inner->findDeviceAuthorization('polled'));
        self::assertEquals(new DeviceAuthorization('approved', 'CODE-approved', 'c', ['poppy:read'], $now->modify('+10 minutes'), 5, DeviceStatus::Approved, 'account-A', ['poppy:read']), $inner->findDeviceAuthorization('approved'));
        self::assertEquals(new DeviceAuthorization('denied', 'CODE-denied', 'c', ['poppy:read'], $now->modify('+10 minutes'), 5, DeviceStatus::Denied), $inner->findDeviceAuthorization('denied'));
        self::assertEquals(new DeviceAuthorization('untouched', 'CODE-untouched', 'c', ['poppy:read'], $now->modify('+10 minutes'), 5), $inner->findDeviceAuthorization('untouched'));
    }

    /** @param \Closure(): PoppyStorage $storage */
    private function start(\Closure $storage): void
    {
        $this->storage = new InterleavingStorage($storage());
        $this->company = new TestCompany(storage: $this->storage);
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
        $this->session = TestCompany::text($this->company->startSession($this->agent), 'session_id');
        $this->deviceCode = TestCompany::text(TestCompany::json($this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        ))), 'device_code');
    }

    /** @return array<string, mixed> */
    private function poll(): array
    {
        return TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_DEVICE_CODE,
            'device_code' => $this->deviceCode,
            'session_id' => $this->session,
        ]));
    }

    /** What the verification page holds after the User entered the code. */
    private function pending(): DeviceAuthorization
    {
        $found = $this->company->server->deviceVerification()->find($this->stored()->userCode);
        self::assertNotNull($found);

        return $found[0];
    }

    private function stored(): DeviceAuthorization
    {
        $stored = $this->company->storage->findDeviceAuthorization(hash('sha256', $this->deviceCode));
        self::assertNotNull($stored);

        return $stored;
    }
}
