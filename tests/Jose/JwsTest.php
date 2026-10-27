<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Jose;

use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Tests\Support\KeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwsTest extends TestCase
{
    public function testParsesHeaderAndClaims(): void
    {
        $jws = Jws::parse(KeyPair::ec()->sign(['sub' => 'u', 'iat' => 5], ['typ' => 'x', 'kid' => 'k']));

        self::assertSame('x', $jws->type());
        self::assertSame('k', $jws->keyId());
        self::assertSame('u', $jws->string('sub'));
        self::assertSame(5, $jws->integer('iat'));
        self::assertNull($jws->integer('sub'));
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        $header = Base64Url::encode('{"alg":"ES256"}');
        $claims = Base64Url::encode('{"a":1}');
        yield 'two segments' => [$header . '.' . $claims];
        yield 'four segments' => [$header . '.' . $claims . '.c2ln.eA'];
        yield 'empty signature' => [$header . '.' . $claims . '.'];
        yield 'padded' => [$header . '=.' . $claims . '.c2ln'];
        yield 'standard alphabet' => [$header . '.' . $claims . '.c2l+'];
        yield 'header not an object' => [Base64Url::encode('[1]') . '.' . $claims . '.c2ln'];
        yield 'payload not JSON' => [$header . '.' . Base64Url::encode('nope') . '.c2ln'];
        yield 'alg missing' => [Base64Url::encode('{"typ":"JWT"}') . '.' . $claims . '.c2ln'];
        yield 'crit present' => [Base64Url::encode('{"alg":"ES256","crit":["b64"],"b64":false}') . '.' . $claims . '.c2ln'];
        yield 'too long' => [str_repeat('a', 20000)];
    }

    #[DataProvider('malformed')]
    public function testRefusesMalformedInput(string $compact): void
    {
        $this->expectException(InvalidJose::class);
        Jws::parse($compact);
    }

    public function testAccessorsIgnoreWrongTypes(): void
    {
        $jws = Jws::parse(KeyPair::ec()->sign(['empty' => '', 'number' => '5', 'list' => [1]], ['typ' => 5, 'kid' => ['x']]));

        self::assertNull($jws->type());
        self::assertNull($jws->keyId());
        self::assertNull($jws->string('empty'));
        self::assertNull($jws->string('list'));
        self::assertNull($jws->integer('number'));
        self::assertSame(\Koh\Poppy\Jose\Algorithm::ES256, $jws->algorithm());
    }

    public function testAcceptsTheMaximumLength(): void
    {
        $jws = KeyPair::ec()->sign(['pad' => str_repeat('a', 12000)]);
        self::assertLessThanOrEqual(16384, strlen($jws));
        self::assertSame(12000, strlen((string) Jws::parse($jws)->string('pad')));
    }

    /** @return iterable<string, array{string}> */
    public static function nonCanonical(): iterable
    {
        yield 'leading junk' => ['!aGk'];
        yield 'trailing junk' => ['aGk!'];
        yield 'trailing newline' => ["aGk\n"];
        yield 'impossible length' => ['aGkaG'];
        yield 'non-zero padding bits' => ['aGl'];
    }

    #[DataProvider('nonCanonical')]
    public function testBase64UrlRejects(string $encoded): void
    {
        $this->expectException(InvalidJose::class);
        Base64Url::decode($encoded);
    }

    public function testBase64UrlRoundTrips(): void
    {
        self::assertSame('', Base64Url::decode(''));
        self::assertSame("\xfb\xff", Base64Url::decode('-_8'));
        self::assertSame('-_8', Base64Url::encode("\xfb\xff"));
    }

    public function testBase64UrlRejectsNonCanonicalSpellings(): void
    {
        self::assertSame('hi', Base64Url::decode('aGk'));

        $this->expectException(InvalidJose::class);
        // 'aGl' decodes to "hi" as well under a lenient decoder; it is not canonical.
        Base64Url::decode('aGl');
    }
}
