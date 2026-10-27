<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Dpop;

use Koh\Poppy\Dpop\DpopVerifier;
use Koh\Poppy\Dpop\TimeSlotNonceSource;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Replay\InMemoryReplayGuard;
use Koh\Poppy\Tests\Support\FrozenClock;
use Koh\Poppy\Tests\Support\KeyPair;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DpopVerifierTest extends TestCase
{
    private const URL = 'https://shop.example/poppy/token';

    private FrozenClock $clock;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->agent = new PersonalAgent();
    }

    public function testAcceptsAValidProofAndReturnsTheThumbprint(): void
    {
        $proof = $this->verifier()->verify($this->request($this->proof()), self::URL);

        self::assertSame(\Koh\Poppy\Jose\Jwk::fromArray($this->agent->dpopKey->publicJwk)->thumbprint(), $proof->jkt);
    }

    public function testHtuIsComparedAfterSyntaxNormalization(): void
    {
        $proof = $this->proof(['htu' => 'HTTPS://Shop.Example:443/poppy/token']);

        self::assertNotEmpty($this->verifier()->verify($this->request($proof), self::URL)->jkt);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function brokenClaims(): iterable
    {
        yield 'other method' => [['htm' => 'GET']];
        yield 'other URL' => [['htu' => 'https://shop.example/poppy/revoke']];
        yield 'other host' => [['htu' => 'https://evil.example/poppy/token']];
        yield 'too old' => [['iat' => 1_793_102_400 - 120]];
        yield 'from the future' => [['iat' => 1_793_102_400 + 120]];
        yield 'no jti' => [['jti' => '']];
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('brokenClaims')]
    public function testRefusesBrokenClaims(array $claims): void
    {
        $this->expectRefusal('invalid_dpop_proof', $this->request($this->proof($claims)));
    }

    public function testRefusesAPrivateKeyInTheHeader(): void
    {
        $key = $this->agent->dpopKey;
        $proof = $key->sign(['jti' => PersonalAgent::jti(), 'htm' => 'POST', 'htu' => self::URL, 'iat' => $this->now()], [
            'typ' => 'dpop+jwt',
            'jwk' => $key->publicJwk + ['d' => 'AAAA'],
        ]);

        $this->expectRefusal('invalid_dpop_proof', $this->request($proof));
    }

    public function testRefusesAWrongType(): void
    {
        $key = $this->agent->dpopKey;
        $proof = $key->sign(['jti' => PersonalAgent::jti(), 'htm' => 'POST', 'htu' => self::URL, 'iat' => $this->now()], ['typ' => 'JWT', 'jwk' => $key->publicJwk]);

        $this->expectRefusal('invalid_dpop_proof', $this->request($proof));
    }

    public function testRefusesAnAlgorithmNotAccepted(): void
    {
        $this->expectRefusal('invalid_dpop_proof', $this->request($this->proof(key: KeyPair::rsa())));
    }

    public function testRefusesTwoHeaders(): void
    {
        $request = $this->request($this->proof())->withAddedHeader('DPoP', $this->proof());

        $this->expectRefusal('invalid_dpop_proof', $request);
    }

    public function testRefusesAReplayWhereReplaysMatter(): void
    {
        $verifier = $this->verifier();
        $request = $this->request($this->proof());

        $verifier->verify($request, self::URL, rejectReplays: true);
        $this->expectException(PoppyError::class);
        $verifier->verify($request, self::URL, rejectReplays: true);
    }

    public function testAsksForANonceWhenOneIsRequired(): void
    {
        $nonces = new TimeSlotNonceSource(str_repeat('s', 32), $this->clock);
        $verifier = new DpopVerifier(new InMemoryReplayGuard(), $this->clock, [Algorithm::ES256], nonces: $nonces);

        try {
            $verifier->verify($this->request($this->proof()), self::URL);
            self::fail('expected use_dpop_nonce');
        } catch (PoppyError $error) {
            self::assertSame('use_dpop_nonce', $error->error);
            self::assertSame($nonces->current(), $error->headers['DPoP-Nonce']);
        }

        self::assertNotEmpty($verifier->verify($this->request($this->proof(['nonce' => $nonces->current()])), self::URL)->jkt);
    }

    public function testRequiresEs256(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new DpopVerifier(new InMemoryReplayGuard(), $this->clock, [Algorithm::RS256]);
    }

    private function verifier(): DpopVerifier
    {
        return new DpopVerifier(new InMemoryReplayGuard(), $this->clock);
    }

    /** @param array<string, mixed> $claims */
    private function proof(array $claims = [], ?KeyPair $key = null): string
    {
        if (is_int($claims['iat'] ?? null)) {
            $claims['iat'] = $claims['iat'] - 1_793_102_400 + $this->now();
        }

        return $this->agent->dpopProof('POST', self::URL, $this->clock->now(), null, $claims, $key);
    }

    private function request(string $proof): ServerRequest
    {
        return (new ServerRequest('POST', self::URL))->withHeader('DPoP', $proof);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    private function expectRefusal(string $error, ServerRequest $request): void
    {
        try {
            $this->verifier()->verify($request, self::URL);
        } catch (PoppyError $exception) {
            self::assertSame($error, $exception->error);

            return;
        }

        self::fail('expected ' . $error);
    }
}
