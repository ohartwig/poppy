<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Resource;

use Koh\Poppy\Exception\PoppyError;

/**
 * The WWW-Authenticate header for a refused API request (Poppy 0.2,
 * section 6; RFC 9449 §7.1, RFC 6750 §3, RFC 9728 §5.1).
 *
 * An MCP server answers with a challenge for every scheme it accepts — Bearer
 * always, DPoP when it verifies proofs — each pointing at its protected
 * resource metadata, so an MCP client that knows nothing of Poppy still finds
 * its way to the authorization server.
 */
final class Challenge
{
    /**
     * @param list<string> $dpopAlgorithms the algorithms the DPoP verifier accepts
     * @param bool         $bearer         whether Bearer is accepted here (an MCP server without DPoP, or any MCP server for plain MCP clients)
     * @param bool         $dpop           whether DPoP is accepted here
     */
    public static function header(PoppyError $error, array $dpopAlgorithms, bool $dpop = true, bool $bearer = false, ?string $resourceMetadata = null): string
    {
        $parameters = ['error="' . self::quote($error->error) . '"', 'error_description="' . self::quote($error->getMessage()) . '"'];
        if (isset($error->extra['scope'])) {
            $parameters[] = 'scope="' . self::quote($error->extra['scope']) . '"';
        }
        if ($resourceMetadata !== null) {
            $parameters[] = 'resource_metadata="' . self::quote($resourceMetadata) . '"';
        }

        $challenges = [];
        if ($dpop) {
            $challenges[] = 'DPoP ' . implode(', ', [...$parameters, 'algs="' . implode(' ', $dpopAlgorithms) . '"']);
        }
        if ($bearer) {
            $challenges[] = 'Bearer ' . implode(', ', $parameters);
        }

        return implode(', ', $challenges);
    }

    private static function quote(string $value): string
    {
        // RFC 9110 quoted-string; descriptions are fixed text, but stay safe if that changes.
        return addcslashes(preg_replace('/[^\x20-\x7e]/', '', $value) ?? '', '"\\');
    }
}
