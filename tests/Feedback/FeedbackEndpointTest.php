<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Feedback;

use Koh\Poppy\Feedback\FeedbackReport;
use Koh\Poppy\Feedback\FeedbackSink;
use Koh\Poppy\Resource\SessionContext;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class FeedbackEndpointTest extends TestCase
{
    private const ENDPOINT = 'https://shop.example/poppy/feedback';

    public function testRecordsAReportWithASessionToken(): void
    {
        $company = new TestCompany();
        $agent = new PersonalAgent();
        $agent->publish($company->http);
        $token = TestCompany::text($company->startSession($agent, 'usr_1'), 'access_token');

        $sink = new class implements FeedbackSink {
            /** @var list<array{FeedbackReport, SessionContext}> */
            public array $reports = [];

            public function record(FeedbackReport $report, SessionContext $session, \DateTimeImmutable $receivedAt): void
            {
                $this->reports[] = [$report, $session];
            }
        };

        $endpoint = $company->server->feedbackEndpoint(self::ENDPOINT, $sink);
        $request = (new ServerRequest('POST', self::ENDPOINT))
            ->withHeader('Authorization', 'DPoP ' . $token)
            ->withHeader('DPoP', $agent->dpopProof('POST', self::ENDPOINT, $company->clock->now(), $token))
            ->withBody((new Psr17Factory())->createStream('{"kind":"missing","task":"Pay with a gift card","description":"No field for a gift card at checkout."}'));

        self::assertSame(202, $endpoint->handle($request)->getStatusCode());
        self::assertCount(1, $sink->reports);
        self::assertSame('usr_1', $sink->reports[0][1]->userId);

        $unauthenticated = (new ServerRequest('POST', self::ENDPOINT))->withBody((new Psr17Factory())->createStream('{}'));
        $refused = $endpoint->handle($unauthenticated);
        self::assertSame(401, $refused->getStatusCode());
        self::assertStringStartsWith('DPoP error="invalid_token"', $refused->getHeaderLine('WWW-Authenticate'));
    }

    public function testAcceptsUnknownKindsAndRefusesOversizedText(): void
    {
        self::assertSame('future-kind', FeedbackReport::fromJson('{"kind":"future-kind","task":"t","description":"d"}')->kind);

        $this->expectException(\Koh\Poppy\Exception\PoppyError::class);
        FeedbackReport::fromJson(json_encode(['kind' => 'missing', 'task' => str_repeat('x', 201), 'description' => 'd'], JSON_THROW_ON_ERROR));
    }
}
