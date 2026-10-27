<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Feedback;

use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Resource\Challenge;
use Koh\Poppy\Resource\ResourceGuard;
use Koh\Poppy\Server\JsonResponder;
use Koh\Poppy\Server\NoRateLimit;
use Koh\Poppy\Server\RateLimiter;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * `POST {feedback.endpoint}` (Poppy 0.2, section 8): a Session Token, signed
 * in or out, and no scope; 202 with no body.
 */
final readonly class FeedbackEndpoint
{
    private const MAX_BYTES = 8192;

    /** @param list<string> $dpopAlgorithms */
    public function __construct(
        private string $endpoint,
        private ResourceGuard $guard,
        private FeedbackSink $sink,
        private JsonResponder $responder,
        private ClockInterface $clock,
        private array $dpopAlgorithms,
        private RateLimiter $rateLimiter = new NoRateLimit(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw PoppyError::invalidRequest('The feedback endpoint accepts POST only.');
            }
            $session = $this->guard->authenticate($request, $this->endpoint);
        } catch (PoppyError $error) {
            $response = $this->responder->error($error);

            return $error->status === 401 || $error->status === 403
                ? $response->withHeader('WWW-Authenticate', Challenge::header($error, $this->dpopAlgorithms))
                : $response;
        }

        try {
            $retryAfter = $this->rateLimiter->hit('feedback', $session->clientId);
            if ($retryAfter !== null) {
                throw PoppyError::rateLimited($retryAfter);
            }

            $body = (string) $request->getBody();
            if (strlen($body) > self::MAX_BYTES) {
                throw PoppyError::invalidRequest('The report is too large.');
            }

            $this->sink->record(FeedbackReport::fromJson($body), $session, $this->clock->now());
        } catch (PoppyError $error) {
            // Section 8 points to 7.13 for these: a body with `error` only.
            return $this->responder->json(['error' => $error->error], $error->status, $error->headers);
        }

        return $this->responder->empty(202);
    }
}
