<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Discovery;

use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Server\TokenEndpoint;

/**
 * The issuer's RFC 8414 metadata (Poppy 0.2, 3.2), and where it is served.
 *
 * `poppy_domains` is the issuer's half of the two-way check: it lists every
 * domain whose poppy.json names this issuer. `protected_resources` carries the
 * same binding in the form draft 0.3 uses (`https://{domain}`), so moving to
 * 0.3 is a version bump rather than a migration; 0.2 agents ignore it, as they
 * must ignore every field they do not know.
 */
final class AuthorizationServerMetadata
{
    /**
     * @param list<string> $dpopAlgorithms
     * @param list<string> $assertionAlgorithms
     *
     * @return array<string, mixed>
     */
    public static function build(ServerConfiguration $configuration, array $dpopAlgorithms, array $assertionAlgorithms): array
    {
        $grants = [TokenEndpoint::GRANT_JWT_BEARER, 'refresh_token'];
        if ($configuration->hasDirectSignIn()) {
            $grants[] = 'authorization_code';
        }
        if ($configuration->hasDeviceSignIn()) {
            $grants[] = TokenEndpoint::GRANT_DEVICE_CODE;
        }

        $endpoints = $configuration->endpoints;
        $metadata = [
            'issuer' => $configuration->issuer,
            'token_endpoint' => $endpoints->token,
            'revocation_endpoint' => $endpoints->revocation,
            'grant_types_supported' => $grants,
            'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => $assertionAlgorithms,
            'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'dpop_signing_alg_values_supported' => $dpopAlgorithms,
            'client_id_metadata_document_supported' => true,
            'poppy_domains' => array_map('strtolower', $configuration->domains),
            'protected_resources' => array_map(static fn (string $domain): string => 'https://' . strtolower($domain), $configuration->domains),
        ];

        if ($configuration->hasDirectSignIn()) {
            $metadata['authorization_endpoint'] = $endpoints->authorization;
            $metadata['response_types_supported'] = ['code'];
            $metadata['code_challenge_methods_supported'] = ['S256'];
            $metadata['authorization_response_iss_parameter_supported'] = true;
        }
        if ($configuration->hasDeviceSignIn()) {
            $metadata['device_authorization_endpoint'] = $endpoints->deviceAuthorization;
        }

        $scopes = $configuration->grantableScopes();
        if ($scopes !== []) {
            $metadata['scopes_supported'] = $scopes;
        }

        foreach ($configuration->apis as $api) {
            if ($api->resource !== null) {
                $metadata['protected_resources'][] = $api->resource;
            }
        }

        return $metadata;
    }

    /**
     * RFC 8414 §3.1: the well-known segment goes between the host and the
     * issuer's path — https://shop.example/poppy is described at
     * https://shop.example/.well-known/oauth-authorization-server/poppy.
     */
    public static function url(string $issuer): string
    {
        $parts = parse_url($issuer);
        $path = is_array($parts) ? ($parts['path'] ?? '') : '';
        $authority = substr($issuer, 0, strlen($issuer) - strlen($path));

        return $authority . '/.well-known/oauth-authorization-server' . rtrim($path, '/');
    }

    /** The path below the host, for routing. */
    public static function path(string $issuer): string
    {
        return (string) parse_url(self::url($issuer), PHP_URL_PATH);
    }
}
