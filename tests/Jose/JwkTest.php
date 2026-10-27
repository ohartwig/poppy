<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Jose;

use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jwk;
use Koh\Poppy\Jose\JwkSet;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Tests\Support\KeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwkTest extends TestCase
{
    /** RFC 7515 Appendix A.3: the ES256 example, public half of the key. */
    public function testVerifiesTheRfc7515Es256Example(): void
    {
        $key = Jwk::fromArray([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);
        $jws = Jws::parse('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q');

        self::assertTrue($key->verify(Algorithm::ES256, $jws->signingInput, $jws->signature));
        self::assertFalse($key->verify(Algorithm::ES256, $jws->signingInput . 'x', $jws->signature));
    }

    /** RFC 7638 §3.1: the thumbprint of the RFC 7517 Appendix A.1 RSA key. */
    public function testComputesTheRfc7638Thumbprint(): void
    {
        $key = Jwk::fromArray([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $key->thumbprint());
    }

    /** @return iterable<string, array{KeyPair, Algorithm}> */
    public static function generatedKeys(): iterable
    {
        yield 'ES256' => [KeyPair::ec('P-256'), Algorithm::ES256];
        yield 'ES384' => [KeyPair::ec('P-384'), Algorithm::ES384];
        yield 'RS256' => [KeyPair::rsa(), Algorithm::RS256];
        yield 'EdDSA' => [KeyPair::ed25519(), Algorithm::EdDSA];
    }

    #[DataProvider('generatedKeys')]
    public function testVerifiesSignaturesFromRealKeys(KeyPair $pair, Algorithm $algorithm): void
    {
        $jws = Jws::parse($pair->sign(['hello' => 'world']));
        $key = Jwk::fromArray($pair->publicJwk);

        self::assertTrue($key->verify($algorithm, $jws->signingInput, $jws->signature));
        self::assertFalse($key->verify($algorithm, $jws->signingInput, strrev($jws->signature)));
    }

    public function testAKeyNeverVerifiesForAnotherAlgorithmFamily(): void
    {
        $pair = KeyPair::ec();
        $jws = Jws::parse($pair->sign(['a' => 1]));
        $key = Jwk::fromArray($pair->publicJwk);

        self::assertFalse($key->supports(Algorithm::RS256));
        self::assertFalse($key->supports(Algorithm::ES384));
        self::assertFalse($key->verify(Algorithm::RS256, $jws->signingInput, $jws->signature));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function unusableKeys(): iterable
    {
        $ec = KeyPair::ec()->publicJwk;
        yield 'private EC key' => [$ec + ['d' => 'AAAA']];
        yield 'symmetric key' => [['kty' => 'oct', 'k' => 'c2VjcmV0']];
        yield 'encryption key' => [$ec + ['use' => 'enc']];
        yield 'unknown curve' => [['crv' => 'P-521'] + $ec];
        yield 'short coordinate' => [['x' => 'AAAA'] + $ec];
        yield 'point not on curve' => [['y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', 'x' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] + $ec];
        yield 'RSA under 2048 bits' => [KeyPair::rsa(1024)->publicJwk];
        yield 'alg not matching' => [$ec + ['alg' => 'RS256']];
        yield 'padded base64' => [['x' => $ec['x'] . '='] + $ec];
        yield 'key_ops without verify' => [$ec + ['key_ops' => ['sign']]];
        yield 'key_ops not a list' => [$ec + ['key_ops' => 'verify']];
        yield 'kid not a string' => [$ec + ['kid' => 5]];
        yield 'unsupported alg' => [$ec + ['alg' => 'HS256']];
        yield 'unknown kty' => [['kty' => 'XYZ']];
        yield 'missing x' => [['kty' => 'EC', 'crv' => 'P-256', 'y' => $ec['y']]];
        yield 'empty y' => [['kty' => 'EC', 'crv' => 'P-256', 'x' => $ec['x'], 'y' => '']];
        yield 'RSA exponent too long' => [['e' => 'AQABAQAB'] + KeyPair::rsa()->publicJwk];
        yield 'RSA exponent zero' => [['e' => 'AA'] + KeyPair::rsa()->publicJwk];
        yield 'Ed448' => [['kty' => 'OKP', 'crv' => 'Ed448', 'x' => 'AAAA']];
        yield 'Ed25519 short key' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'AAAA']];
    }

    public function testAcceptsKeyOpsWithVerifyAndUseSig(): void
    {
        $ec = KeyPair::ec()->publicJwk;
        $key = Jwk::fromArray($ec + ['key_ops' => ['verify'], 'use' => 'sig', 'kid' => 'k1', 'alg' => 'ES256']);

        self::assertSame('k1', $key->keyId);
        self::assertSame(Algorithm::ES256, $key->algorithm);
        self::assertSame('EC', $key->keyType);
        self::assertSame('P-256', $key->curve);
    }

    public function testEd25519KeysServeBothNames(): void
    {
        $pair = KeyPair::ed25519();
        $named = Jwk::fromArray($pair->publicJwk + ['alg' => 'EdDSA']);
        $jws = Jws::parse($pair->sign(['a' => 1]));

        self::assertTrue($named->supports(Algorithm::EdDSA));
        self::assertTrue($named->supports(Algorithm::Ed25519));
        self::assertFalse($named->supports(Algorithm::ES256));
        self::assertTrue($named->verify(Algorithm::Ed25519, $jws->signingInput, $jws->signature));
        self::assertFalse($named->verify(Algorithm::EdDSA, $jws->signingInput, substr($jws->signature, 1)), 'wrong signature length');
    }

    public function testAKeyPinnedToOneAlgorithmRefusesAnother(): void
    {
        $rsa = KeyPair::rsa();
        $key = Jwk::fromArray($rsa->publicJwk + ['alg' => 'RS256']);

        self::assertTrue($key->supports(Algorithm::RS256));
        self::assertNull($key->curve);

        $ec = Jwk::fromArray(KeyPair::ec('P-384')->publicJwk + ['alg' => 'ES384']);
        self::assertFalse($ec->supports(Algorithm::ES256));
        self::assertTrue($ec->supports(Algorithm::ES384));
    }

    public function testAnEcSignatureOfTheWrongLengthFails(): void
    {
        $pair = KeyPair::ec();
        $jws = Jws::parse($pair->sign(['a' => 1]));
        $key = Jwk::fromArray($pair->publicJwk);

        self::assertFalse($key->verify(Algorithm::ES256, $jws->signingInput, $jws->signature . "\x00"));
        self::assertFalse($key->verify(Algorithm::ES256, $jws->signingInput, substr($jws->signature, 0, 63)));
    }

    public function testThumbprintsDifferPerKeyAndIgnoreExtraMembers(): void
    {
        $pair = KeyPair::ec();
        $plain = Jwk::fromArray($pair->publicJwk);
        $labelled = Jwk::fromArray($pair->publicJwk + ['kid' => 'x', 'use' => 'sig']);

        self::assertSame($plain->thumbprint(), $labelled->thumbprint());
        self::assertNotSame($plain->thumbprint(), Jwk::fromArray(KeyPair::ec()->publicJwk)->thumbprint());
        self::assertSame(43, strlen($plain->thumbprint()));
    }

    /** @param array<string, mixed> $jwk */
    #[DataProvider('unusableKeys')]
    public function testRefusesUnusableKeys(array $jwk): void
    {
        $this->expectException(InvalidJose::class);
        Jwk::fromArray($jwk);
    }

    public function testKeySetSkipsUnusableKeysAndSelectsByKid(): void
    {
        $a = KeyPair::ec(kid: 'a');
        $b = KeyPair::ec(kid: 'b');
        $set = JwkSet::fromArray(['keys' => [['kty' => 'oct', 'k' => 'eA'], $a->publicJwk, $b->publicJwk]]);

        self::assertCount(2, $set->keys);
        self::assertTrue($set->verifies(Jws::parse($b->sign(['x' => 1], ['kid' => 'b'])), Algorithm::ES256));
        self::assertFalse($set->verifies(Jws::parse($b->sign(['x' => 1], ['kid' => 'a'])), Algorithm::ES256));
    }

    public function testKeySetWithoutUsableKeysIsAnError(): void
    {
        $this->expectException(InvalidJose::class);
        JwkSet::fromArray(['keys' => [['kty' => 'oct', 'k' => 'eA']]]);
    }
}
