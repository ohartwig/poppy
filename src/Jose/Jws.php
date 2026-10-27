<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

use Koh\Poppy\Exception\InvalidJose;

/**
 * A JWS in compact serialization whose payload is a JSON object of claims.
 *
 * Parsing checks shape only; the signature is not verified here, because which
 * key and which algorithms are acceptable depends on what the token is for.
 * Nothing in a parsed but unverified JWS may be trusted, and callers read the
 * header only to decide how to verify.
 */
final readonly class Jws
{
    /** Generous for a JWT with an embedded RSA key; small enough that nobody parses megabytes. */
    private const MAX_LENGTH = 16384;

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    private function __construct(
        public array $header,
        public array $claims,
        public string $signingInput,
        public string $signature,
    ) {}

    public static function parse(string $compact): self
    {
        if ($compact === '' || strlen($compact) > self::MAX_LENGTH) {
            throw InvalidJose::structure('length');
        }

        $parts = explode('.', $compact);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw InvalidJose::structure('not three non-empty segments');
        }

        $header = self::object(Base64Url::decode($parts[0]), 'header');
        $claims = self::object(Base64Url::decode($parts[1]), 'payload');

        // RFC 7515 §4.1.11: an extension the recipient does not understand makes
        // the JWS invalid. This package understands none, so any `crit` fails.
        if (array_key_exists('crit', $header)) {
            throw InvalidJose::structure('unsupported crit');
        }
        if (!is_string($header['alg'] ?? null)) {
            throw InvalidJose::structure('alg missing');
        }

        return new self($header, $claims, $parts[0] . '.' . $parts[1], Base64Url::decode($parts[2]));
    }

    public function algorithm(): ?Algorithm
    {
        return Algorithm::tryFromHeader($this->header['alg']);
    }

    public function type(): ?string
    {
        $type = $this->header['typ'] ?? null;

        return is_string($type) ? $type : null;
    }

    public function keyId(): ?string
    {
        $keyId = $this->header['kid'] ?? null;

        return is_string($keyId) ? $keyId : null;
    }

    public function string(string $claim): ?string
    {
        $value = $this->claims[$claim] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function integer(string $claim): ?int
    {
        $value = $this->claims[$claim] ?? null;

        return is_int($value) ? $value : null;
    }

    /** @return array<string, mixed> */
    private static function object(string $json, string $part): array
    {
        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw InvalidJose::structure($part . ' is not JSON');
        }

        if (!is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            throw InvalidJose::structure($part . ' is not a JSON object');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
