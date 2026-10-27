<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Discovery\Api;
use Koh\Poppy\Http\Url;

/**
 * Everything the authorization server needs to know about one Company.
 *
 * One configuration is one issuer, and one issuer is one Company (Poppy 0.2,
 * 3.2): a provider hosting several Companies builds one configuration each,
 * never one shared, or the Companies' User IDs and Account Tokens become
 * interchangeable.
 *
 * Direct and Device Sign-In are on when their scope list is non-null. With
 * both null the Company offers signed-out Sessions only, which is a complete
 * and valid deployment.
 */
final readonly class ServerConfiguration
{
    /**
     * @param list<string>          $domains      every domain whose poppy.json names this issuer
     * @param list<string>|null     $directScopes scopes Direct Sign-In can grant, null when it is off
     * @param list<string>|null     $deviceScopes scopes Device Sign-In can grant, null when it is off
     * @param array<string, string> $customScopes the Company's own scopes and their descriptions
     * @param list<Api>             $apis
     */
    public function __construct(
        public string $issuer,
        public array $domains,
        public Endpoints $endpoints,
        public ?array $directScopes = null,
        public ?array $deviceScopes = null,
        public array $customScopes = [],
        public array $apis = [],
        public int $sessionTokenTtl = 3600,
        public int $sessionLifetime = 2592000,
        public ?int $accountTokenTtl = 7776000,
        public int $authorizationCodeTtl = 120,
        public int $deviceCodeTtl = 600,
        public int $deviceInterval = 5,
    ) {
        if (!Url::isHttps($issuer) || parse_url($issuer, PHP_URL_QUERY) !== null || str_ends_with($issuer, '/')) {
            throw new \InvalidArgumentException('The issuer must be an HTTPS URL without query, fragment or trailing slash.');
        }
        if ($domains === []) {
            throw new \InvalidArgumentException('At least one domain must name this issuer.');
        }
        foreach (array_keys($customScopes) as $scope) {
            if (!Scopes::isValidCustom($scope)) {
                throw new \InvalidArgumentException('Custom scopes must be valid scope tokens outside the poppy: namespace.');
            }
        }
        foreach ([...($directScopes ?? []), ...($deviceScopes ?? [])] as $scope) {
            if (!in_array($scope, $this->knownScopes(), true)) {
                throw new \InvalidArgumentException('A sign-in type grants a scope that is neither a Poppy scope nor a declared custom scope.');
            }
        }
        if ($sessionTokenTtl < 60 || $sessionTokenTtl > 86400) {
            throw new \InvalidArgumentException('Session Tokens should last hours, not days (4.2): 60 to 86400 seconds.');
        }
        if ($authorizationCodeTtl < 30 || $authorizationCodeTtl > 600) {
            throw new \InvalidArgumentException('Authorization codes live 30 to 600 seconds.');
        }
    }

    /** @return list<string> */
    public function knownScopes(): array
    {
        return [Scopes::READ, Scopes::WRITE, ...array_keys($this->customScopes)];
    }

    /** @return list<string> every scope some sign-in type can grant */
    public function grantableScopes(): array
    {
        return array_values(array_unique([...($this->directScopes ?? []), ...($this->deviceScopes ?? [])]));
    }

    public function hasDirectSignIn(): bool
    {
        return $this->directScopes !== null && $this->directScopes !== [];
    }

    public function hasDeviceSignIn(): bool
    {
        return $this->deviceScopes !== null && $this->deviceScopes !== [];
    }

    /** The API a `resource` parameter names, or null when it names none of them. */
    public function apiForResource(string $resource): ?Api
    {
        foreach ($this->apis as $api) {
            if ($api->resource !== null && $api->resource === $resource) {
                return $api;
            }
        }

        return null;
    }
}
