<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Exception\PoppyError;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The form parameters of a token, revocation or device authorization request.
 *
 * Read from the raw body rather than trusted from a framework's parsed body,
 * so that a parameter sent twice is caught: RFC 6749 §3.2 forbids repeated
 * parameters, and parse_str() would silently keep the last one — which is how
 * one component reads one value and another a different one.
 *
 * @internal
 */
final class FormParameters
{
    private const MAX_BYTES = 65536;

    /**
     * @return array<string, string>
     *
     * @throws PoppyError invalid_request
     */
    public static function from(ServerRequestInterface $request): array
    {
        $contentType = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
        if ($contentType !== 'application/x-www-form-urlencoded') {
            throw PoppyError::invalidRequest('The body must be application/x-www-form-urlencoded.');
        }

        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $raw = '';
        while (!$body->eof()) {
            $raw .= $body->read(8192);
            if (strlen($raw) > self::MAX_BYTES) {
                throw PoppyError::invalidRequest('The body is too large.');
            }
        }

        $parameters = [];
        foreach ($raw === '' ? [] : explode('&', $raw) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            if (array_key_exists($name, $parameters)) {
                throw PoppyError::invalidRequest('A parameter was sent more than once.');
            }
            $parameters[$name] = urldecode($value);
        }

        return $parameters;
    }
}
