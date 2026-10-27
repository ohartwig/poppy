<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Discovery;

use Koh\Poppy\Http\Url;

/**
 * An API listed in `poppy.json` (Poppy 0.2, section 6).
 *
 * An MCP server is always its own resource: Personal Agents ask for a token
 * with `resource` set to its URL, and only such tokens are accepted there
 * (4.3). Whether it verifies DPoP decides the token type — DPoP when it does,
 * a Bearer token valid at that server alone when it does not. An OpenAPI API
 * always uses DPoP, and has a resource only if the Company wants separate
 * tokens for it.
 */
final readonly class Api
{
    public const OPENAPI = 'openapi';

    public const MCP = 'mcp';

    private function __construct(
        public string $type,
        public string $url,
        public string $description,
        public ?string $resource,
        public bool $dpop,
    ) {
        if (!Url::isHttps($url) || ($resource !== null && !Url::isHttps($resource))) {
            throw new \InvalidArgumentException('API URLs and resources must be HTTPS URLs.');
        }
        $length = mb_strlen(trim($description));
        if ($length === 0 || $length > 200) {
            throw new \InvalidArgumentException('An API needs a short description.');
        }
    }

    /** @param string $url the OpenAPI description document */
    public static function openApi(string $url, string $description, ?string $resource = null): self
    {
        return new self(self::OPENAPI, $url, $description, $resource, true);
    }

    /** @param string $url the Streamable HTTP endpoint of the MCP server */
    public static function mcp(string $url, string $description, bool $supportsDpop): self
    {
        return new self(self::MCP, $url, $description, $url, $supportsDpop);
    }

    public function isMcp(): bool
    {
        return $this->type === self::MCP;
    }

    /** @return array<string, string> */
    public function toArray(): array
    {
        $entry = ['type' => $this->type, 'url' => $this->url, 'description' => trim($this->description)];
        // An MCP server's resource is its url by definition; listing it again says nothing.
        if ($this->resource !== null && !$this->isMcp()) {
            $entry['resource'] = $this->resource;
        }

        return $entry;
    }
}
