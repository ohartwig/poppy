<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Discovery;

use Koh\Poppy\Http\Url;
use Koh\Poppy\Server\ServerConfiguration;

/**
 * `/.well-known/poppy.json` (Poppy 0.2, section 3).
 *
 * Built from what is actually running, never from wishes: `auth` appears only
 * with a server configuration behind it, a sign-in type only when its scopes
 * are configured, the browser-session and feedback endpoints only when the
 * integration serves them. Without a server, the document declares the
 * website alone — `web: {}`, browsed as an ordinary visitor — which is a
 * complete and honest answer.
 */
final readonly class PoppyDocument
{
    public const PROTOCOL_VERSION = '0.2';

    /** @param list<Api> $apis */
    public function __construct(
        private string $organizationName,
        private string $organizationDomain,
        private ?ServerConfiguration $server = null,
        private array $apis = [],
        private bool $web = true,
        private ?string $browserSessionEndpoint = null,
        private ?string $feedbackEndpoint = null,
    ) {
        if (trim($organizationName) === '' || $organizationDomain === '' || Url::host('https://' . $organizationDomain) !== strtolower($organizationDomain)) {
            throw new \InvalidArgumentException('The organization needs a name and a bare host name as its domain.');
        }
        foreach ([$browserSessionEndpoint, $feedbackEndpoint] as $url) {
            if ($url !== null && !Url::isHttps($url)) {
                throw new \InvalidArgumentException('Every URL in poppy.json must be HTTPS.');
            }
        }

        $needsAuth = $apis !== [] || $browserSessionEndpoint !== null || $feedbackEndpoint !== null;
        if ($needsAuth && $server === null) {
            throw new \InvalidArgumentException('APIs, the browser-session endpoint and feedback need an authorization server (auth).');
        }
        if ($server !== null && !in_array(strtolower($organizationDomain), array_map('strtolower', $server->domains), true)) {
            throw new \InvalidArgumentException('The issuer must list this domain in poppy_domains.');
        }
        if (!$web && $apis === []) {
            throw new \InvalidArgumentException('poppy.json needs at least one of agent, apis or web.');
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $document = [
            'protocol_version' => self::PROTOCOL_VERSION,
            'organization' => ['name' => trim($this->organizationName), 'domain' => strtolower($this->organizationDomain)],
        ];

        if ($this->server !== null) {
            $auth = ['issuer' => $this->server->issuer];
            if ($this->server->hasDirectSignIn()) {
                $auth['direct'] = ['scopes' => $this->server->directScopes];
            }
            if ($this->server->hasDeviceSignIn()) {
                $auth['device'] = ['scopes' => $this->server->deviceScopes];
            }

            $granted = $this->server->grantableScopes();
            $custom = array_filter(
                $this->server->customScopes,
                static fn (string $scope): bool => in_array($scope, $granted, true),
                ARRAY_FILTER_USE_KEY,
            );
            if ($custom !== []) {
                $auth['custom_scopes'] = $custom;
            }
            $document['auth'] = $auth;
        }

        if ($this->web) {
            // An empty object, not an empty list: `web` is an object in the specification.
            $document['web'] = $this->browserSessionEndpoint !== null
                ? ['browser_session_endpoint' => $this->browserSessionEndpoint]
                : new \stdClass();
        }

        if ($this->feedbackEndpoint !== null) {
            $document['feedback'] = ['endpoint' => $this->feedbackEndpoint];
        }

        if ($this->apis !== []) {
            $document['apis'] = array_map(static fn (Api $api): array => $api->toArray(), $this->apis);
        }

        return $document;
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
    }
}
