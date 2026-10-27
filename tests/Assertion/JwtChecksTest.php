<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Assertion;

use Koh\Poppy\Assertion\JwtChecks;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Jose\JwkSet;
use Koh\Poppy\Tests\Support\KeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwtChecksTest extends TestCase
{
    private const NOW = 1_800_000_000;

    /** @return iterable<string, array{int|null, int|null, string|null}> */
    public static function lifetimes(): iterable
    {
        yield 'fine' => [self::NOW, self::NOW + 60, null];
        yield 'exactly the maximum' => [self::NOW, self::NOW + 300, null];
        yield 'one second over' => [self::NOW, self::NOW + 301, 'exp must be at most 300 seconds after iat'];
        yield 'exp before iat' => [self::NOW, self::NOW - 1, 'exp must be at most 300 seconds after iat'];
        yield 'exp equals iat' => [self::NOW, self::NOW, 'exp must be at most 300 seconds after iat'];
        yield 'iat within the leeway' => [self::NOW + 30, self::NOW + 60, null];
        yield 'iat beyond the leeway' => [self::NOW + 31, self::NOW + 60, 'issued in the future'];
        yield 'expired within the leeway' => [self::NOW - 60, self::NOW - 29, null];
        yield 'expired beyond the leeway' => [self::NOW - 60, self::NOW - 30, 'expired'];
        yield 'no iat' => [null, self::NOW + 60, 'iat and exp are required integers'];
        yield 'no exp' => [self::NOW, null, 'iat and exp are required integers'];
    }

    #[DataProvider('lifetimes')]
    public function testLifetime(?int $iat, ?int $exp, ?string $failure): void
    {
        $claims = array_filter(['iat' => $iat, 'exp' => $exp], static fn (?int $value): bool => $value !== null);

        self::assertSame($failure, JwtChecks::lifetime(self::jws($claims), new \DateTimeImmutable('@' . self::NOW), 300));
    }

    public function testJtiLength(): void
    {
        self::assertNull(JwtChecks::jti(self::jws(['jti' => str_repeat('a', 22)])));
        self::assertNull(JwtChecks::jti(self::jws(['jti' => str_repeat('a', 256)])));
        self::assertNotNull(JwtChecks::jti(self::jws(['jti' => str_repeat('a', 21)])));
        self::assertNotNull(JwtChecks::jti(self::jws(['jti' => str_repeat('a', 257)])));
        self::assertNotNull(JwtChecks::jti(self::jws([])));
    }

    public function testAudience(): void
    {
        self::assertNull(JwtChecks::audience(self::jws(['aud' => 'https://shop.example/poppy']), 'https://shop.example/poppy'));
        self::assertSame('aud must be exactly https://shop.example/poppy', JwtChecks::audience(self::jws(['aud' => ['https://shop.example/poppy']]), 'https://shop.example/poppy'));
        self::assertNotNull(JwtChecks::audience(self::jws(['aud' => 'https://shop.example/poppy/']), 'https://shop.example/poppy'));
    }

    public function testSignatureNeedsAnAcceptedAlgorithmAndAKnownKey(): void
    {
        $key = KeyPair::ec();
        $set = JwkSet::fromArray(['keys' => [$key->publicJwk]]);
        $jws = Jws::parse($key->sign(['a' => 1]));

        self::assertNull(JwtChecks::signature($jws, $set, [Algorithm::ES256]));
        self::assertSame('signature algorithm not accepted', JwtChecks::signature($jws, $set, [Algorithm::RS256]));
        self::assertSame('signature does not verify with the Personal Agent\'s keys', JwtChecks::signature($jws, JwkSet::fromArray(['keys' => [KeyPair::ec()->publicJwk]]), [Algorithm::ES256]));
    }

    public function testRemembersUntilExpiryPlusLeeway(): void
    {
        self::assertSame(self::NOW + 90, JwtChecks::rememberUntil(self::jws(['exp' => self::NOW + 60]))->getTimestamp());
    }

    /** @param array<string, mixed> $claims */
    private static function jws(array $claims): Jws
    {
        return Jws::parse(KeyPair::ec()->sign($claims));
    }
}
