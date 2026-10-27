<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Dpop\TimeSlotNonceSource;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Feedback\FeedbackReport;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Replay\InMemoryReplayGuard;
use Koh\Poppy\Server\FormParameters;
use Koh\Poppy\Server\Pkce;
use Koh\Poppy\Server\Scopes;
use Koh\Poppy\Server\Secrets;
use Koh\Poppy\Tests\Support\FrozenClock;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The small pieces the endpoints are built from. */
final class PrimitivesTest extends TestCase
{
    public function testFormParameters(): void
    {
        $request = (new ServerRequest('POST', 'https://shop.example/t'))
            ->withHeader('Content-Type', 'Application/X-WWW-Form-Urlencoded ; charset=UTF-8')
            ->withBody((new Psr17Factory())->createStream('a=1&&b=x%3Dy&c&d=%20'));

        self::assertSame(['a' => '1', 'b' => 'x=y', 'c' => '', 'd' => ' '], FormParameters::from($request));
    }

    public function testFormParametersReadAStreamThatWasAlreadyRead(): void
    {
        $body = (new Psr17Factory())->createStream('a=1');
        $body->getContents();
        $request = (new ServerRequest('POST', 'https://shop.example/t'))->withHeader('Content-Type', 'application/x-www-form-urlencoded')->withBody($body);

        self::assertSame(['a' => '1'], FormParameters::from($request));
    }

    /** @return iterable<string, array{string, string}> */
    public static function badForms(): iterable
    {
        yield 'JSON' => ['application/json', '{}'];
        yield 'no content type' => ['', 'a=1'];
        yield 'too large' => ['application/x-www-form-urlencoded', 'a=' . str_repeat('x', 65535)];
        yield 'repeated' => ['application/x-www-form-urlencoded', 'a=1&a=2'];
        yield 'repeated after decoding' => ['application/x-www-form-urlencoded', 'a=1&%61=2'];
    }

    #[DataProvider('badForms')]
    public function testFormParametersRefuse(string $contentType, string $body): void
    {
        $request = (new ServerRequest('POST', 'https://shop.example/t'))->withHeader('Content-Type', $contentType)->withBody((new Psr17Factory())->createStream($body));

        $this->expectException(PoppyError::class);
        FormParameters::from($request);
    }

    public function testFormParametersAtTheSizeLimit(): void
    {
        $request = (new ServerRequest('POST', 'https://shop.example/t'))->withHeader('Content-Type', 'application/x-www-form-urlencoded')->withBody((new Psr17Factory())->createStream('a=' . str_repeat('x', 65534)));

        self::assertSame(65534, strlen(FormParameters::from($request)['a']));
    }

    public function testScopes(): void
    {
        self::assertSame(['poppy:read', 'poppy:write'], Scopes::parse('poppy:read poppy:write poppy:read', ['poppy:read', 'poppy:write']));
        self::assertSame([], Scopes::parse(null, [], required: false));
        self::assertSame([], Scopes::parse('', [], required: false));
        self::assertSame('a b', Scopes::format(['a', 'b']));
        self::assertTrue(Scopes::isValidCustom('addresses'));
        self::assertFalse(Scopes::isValidCustom('poppy:addresses'));
        self::assertFalse(Scopes::isValidCustom('quote"d'));

        foreach ([null, '', 'poppy:read  poppy:write', 'unknown', 'bad"scope', ['poppy:read']] as $input) {
            try {
                Scopes::parse($input, ['poppy:read', 'poppy:write', 'bad"scope']);
                self::fail(var_export($input, true) . ' should be refused');
            } catch (PoppyError $error) {
                self::assertSame('invalid_scope', $error->error);
            }
        }
    }

    public function testSecrets(): void
    {
        self::assertMatchesRegularExpression('/^pat_[A-Za-z0-9_-]{43}$/', Secrets::token('pat_'));
        self::assertMatchesRegularExpression('/^ses_[A-Za-z0-9_-]{22}$/', Secrets::id('ses_'));
        self::assertNotSame(Secrets::token('x'), Secrets::token('x'));
        self::assertSame(hash('sha256', 'abc'), Secrets::hash('abc'));

        for ($i = 0; $i < 50; ++$i) {
            self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', Secrets::userCode());
        }

        self::assertSame('WDJB-MJHT', Secrets::normalizeUserCode(' wdjb mjht '));
        self::assertSame('WDJB-MJHT', Secrets::normalizeUserCode('WDJBMJHT'));
        self::assertSame('WDJB-MJHT', Secrets::normalizeUserCode('wd-jb-mj-ht'));
        self::assertNull(Secrets::normalizeUserCode('WDJB-MJH'));
        self::assertNull(Secrets::normalizeUserCode('WDJB-MJHTX'));
        self::assertNull(Secrets::normalizeUserCode('WDJA-MJHT'), 'vowels are not in the alphabet');
    }

    public function testPkce(): void
    {
        $verifier = str_repeat('a', 43);
        $challenge = Base64Url::encode(hash('sha256', $verifier, true));

        self::assertTrue(Pkce::verify($verifier, $challenge));
        self::assertTrue(Pkce::isValidChallenge($challenge));
        self::assertFalse(Pkce::isValidChallenge($challenge . 'a'));
        self::assertFalse(Pkce::verify(str_repeat('a', 42), Base64Url::encode(hash('sha256', str_repeat('a', 42), true))), 'a verifier is at least 43 characters');
        self::assertTrue(Pkce::verify(str_repeat('b', 128), Base64Url::encode(hash('sha256', str_repeat('b', 128), true))));
        self::assertFalse(Pkce::verify(str_repeat('b', 129), Base64Url::encode(hash('sha256', str_repeat('b', 129), true))));
    }

    public function testTimeSlotNonces(): void
    {
        $clock = new FrozenClock(new \DateTimeImmutable('@1800000000'));
        $nonces = new TimeSlotNonceSource(str_repeat('k', 32), $clock, 300);
        $nonce = $nonces->current();

        self::assertTrue($nonces->isValid($nonce));
        $clock->advance(300);
        self::assertTrue($nonces->isValid($nonce), 'valid in the following slot');
        self::assertNotSame($nonce, $nonces->current());
        $clock->advance(300);
        self::assertFalse($nonces->isValid($nonce), 'not two slots later');

        $other = new TimeSlotNonceSource(str_repeat('o', 32), $clock, 300);
        self::assertFalse($other->isValid($nonces->current()), 'another secret, another nonce');
    }

    public function testTimeSlotNoncesNeedASecretAndASensibleSlot(): void
    {
        $clock = new FrozenClock();
        new TimeSlotNonceSource(str_repeat('k', 32), $clock, 30);

        foreach ([[str_repeat('k', 31), 300], [str_repeat('k', 32), 29]] as [$secret, $slot]) {
            try {
                new TimeSlotNonceSource($secret, $clock, $slot);
                self::fail('expected a refusal');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testInMemoryReplayGuardScopesIds(): void
    {
        $guard = new InMemoryReplayGuard();
        $until = new \DateTimeImmutable();

        self::assertTrue($guard->claim('a', 'x', $until));
        self::assertFalse($guard->claim('a', 'x', $until));
        self::assertTrue($guard->claim('b', 'x', $until));
        self::assertTrue($guard->claim('a', 'y', $until));
    }

    public function testFeedbackReportBoundaries(): void
    {
        $report = FeedbackReport::fromJson(json_encode(['kind' => str_repeat('k', 64), 'task' => ' ' . str_repeat('ä', 200) . ' ', 'description' => str_repeat('ö', 2000)], JSON_THROW_ON_ERROR));
        self::assertSame(200, mb_strlen($report->task));
        self::assertSame(2000, mb_strlen($report->description));

        foreach ([
            '{"kind":"' . str_repeat('k', 65) . '","task":"t","description":"d"}',
            '{"kind":"missing","task":"t","description":"' . str_repeat('ö', 2001) . '"}',
            '{"kind":"missing","task":"  ","description":"d"}',
            '{"kind":"missing","task":"t","description":" "}',
            '{"kind":"","task":"t","description":"d"}',
            '{"kind":"missing","task":5,"description":"d"}',
            '{"kind":"missing","description":"d"}',
            '"text"',
            'nope',
        ] as $body) {
            try {
                FeedbackReport::fromJson($body);
                self::fail($body . ' should be refused');
            } catch (PoppyError $error) {
                self::assertSame('invalid_request', $error->error);
            }
        }
    }
}
