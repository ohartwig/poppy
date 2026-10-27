<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Exception\PoppyError;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * JSON responses of the protocol endpoints. Everything they return is either a
 * token or about one, so nothing is cacheable (RFC 6749 §5.1).
 *
 * @internal
 */
final readonly class JsonResponder
{
    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @param array<string, mixed>  $body
     * @param array<string, string> $headers
     */
    public function json(array $body, int $status = 200, array $headers = []): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withBody($this->streamFactory->createStream(json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)));

        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    public function error(PoppyError $error): ResponseInterface
    {
        // No WWW-Authenticate on invalid_client: RFC 6749 §5.2 asks for it only
        // when the client authenticated through the Authorization header, and
        // a client assertion travels in the body.
        return $this->json($error->body(), $error->status, $error->headers);
    }

    public function empty(int $status): ResponseInterface
    {
        return $this->responseFactory->createResponse($status)->withHeader('Cache-Control', 'no-store');
    }
}
