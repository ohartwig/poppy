<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\TestCase;

/** A Personal Agent's browser joining a Session (Poppy 0.2, section 5). */
final class BrowserSessionsTest extends TestCase
{
    private const ENDPOINT = 'https://shop.example/poppy/browser-session';

    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->company = new TestCompany();
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testJoinsTheSession(): void
    {
        $sessionId = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $assertion = $this->agent->browserAssertion(self::ENDPOINT, 'usr_1', $sessionId, 'https://www.shop.example/orders', $this->company->clock->now());

        [$session, $returnTo] = $this->sessions()->join($assertion);

        self::assertSame($sessionId, $session->id);
        self::assertSame('https://www.shop.example/orders', $returnTo);
        self::assertSame($sessionId, $this->sessions()->current($sessionId)?->id);
    }

    public function testRefusesAReplay(): void
    {
        $sessionId = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $assertion = $this->agent->browserAssertion(self::ENDPOINT, 'usr_1', $sessionId, 'https://shop.example/', $this->company->clock->now());
        $sessions = $this->sessions();

        $sessions->join($assertion);
        $this->expectException(PoppyError::class);
        $sessions->join($assertion);
    }

    public function testRefusesAnotherUsersSession(): void
    {
        $sessionId = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');

        $this->expectException(PoppyError::class);
        $this->sessions()->join($this->agent->browserAssertion(self::ENDPOINT, 'usr_2', $sessionId, 'https://shop.example/', $this->company->clock->now()));
    }

    public function testRefusesAReturnUrlOffTheDomain(): void
    {
        $sessionId = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');

        $this->expectException(PoppyError::class);
        $this->sessions()->join($this->agent->browserAssertion(self::ENDPOINT, 'usr_1', $sessionId, 'https://shop.example.evil.example/', $this->company->clock->now()));
    }

    public function testASessionAssertionIsNotABrowserAssertion(): void
    {
        $this->expectException(PoppyError::class);
        $this->sessions()->join($this->agent->sessionAssertion(self::ENDPOINT, 'usr_1', $this->company->clock->now()));
    }

    private function sessions(): \Koh\Poppy\Server\BrowserSessions
    {
        return $this->company->server->browserSessions(self::ENDPOINT, 'shop.example');
    }
}
