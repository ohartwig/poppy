<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

use Koh\Poppy\Exception\InvalidJose;

/**
 * A public JSON Web Key (RFC 7517) that can verify signatures.
 *
 * Construction refuses anything that is not a usable public key: private
 * members, symmetric keys, unknown curves and RSA moduli under 2048 bits. A key
 * set fetched from a Personal Agent or a key in a DPoP header is attacker
 * input, so the checks run once here rather than at every use. That a private
 * key is rejected matters for DPoP too: RFC 9449 requires the header key to be
 * public, and a client that leaks its private key there has a key nobody else
 * should accept.
 */
final readonly class Jwk
{
    private const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    private const MIN_RSA_BITS = 2048;

    /** @param array<string, string> $thumbprintMembers */
    private function __construct(
        public string $keyType,
        public ?string $curve,
        public ?string $keyId,
        public ?Algorithm $algorithm,
        private array $thumbprintMembers,
        private string $material,
    ) {}

    /** @param array<mixed> $jwk */
    public static function fromArray(array $jwk): self
    {
        foreach (self::PRIVATE_MEMBERS as $member) {
            if (array_key_exists($member, $jwk)) {
                throw InvalidJose::key('private or symmetric key material');
            }
        }

        $use = $jwk['use'] ?? null;
        if ($use !== null && $use !== 'sig') {
            throw InvalidJose::key('not a signature key');
        }

        $keyOps = $jwk['key_ops'] ?? null;
        if ($keyOps !== null && (!is_array($keyOps) || !in_array('verify', $keyOps, true))) {
            throw InvalidJose::key('key_ops does not allow verify');
        }

        $keyId = $jwk['kid'] ?? null;
        if ($keyId !== null && !is_string($keyId)) {
            throw InvalidJose::key('kid is not a string');
        }

        $algorithm = null;
        if (array_key_exists('alg', $jwk)) {
            $algorithm = Algorithm::tryFromHeader($jwk['alg']) ?? throw InvalidJose::key('unsupported alg');
        }

        $key = match ($jwk['kty'] ?? null) {
            'EC' => self::ec($jwk, $keyId, $algorithm),
            'RSA' => self::rsa($jwk, $keyId, $algorithm),
            'OKP' => self::okp($jwk, $keyId, $algorithm),
            default => throw InvalidJose::key('unsupported kty'),
        };

        if ($algorithm !== null && !$key->supports($algorithm)) {
            throw InvalidJose::key('alg does not match the key');
        }

        return $key;
    }

    public function supports(Algorithm $algorithm): bool
    {
        if ($this->algorithm !== null && $this->algorithm !== $algorithm
            && !($this->isEd25519() && in_array($algorithm, [Algorithm::EdDSA, Algorithm::Ed25519], true))) {
            return false;
        }

        return $algorithm->keyType() === $this->keyType && $algorithm->curve() === $this->curve;
    }

    public function verify(Algorithm $algorithm, string $signingInput, string $signature): bool
    {
        if (!$this->supports($algorithm)) {
            return false;
        }

        if ($this->isEd25519()) {
            return $this->material !== '' && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                && sodium_crypto_sign_verify_detached($signature, $signingInput, $this->material);
        }

        $ecLength = $algorithm->ecSignatureLength();
        if ($ecLength !== null) {
            if (strlen($signature) !== $ecLength) {
                return false;
            }
            $signature = Der::ecdsaSignature($signature);
        }

        $publicKey = openssl_pkey_get_public($this->material);
        if ($publicKey === false) {
            return false;
        }

        return openssl_verify($signingInput, $signature, $publicKey, $algorithm->digest()) === 1;
    }

    /** RFC 7638 thumbprint, base64url — the `jkt` a DPoP-bound token is tied to. */
    public function thumbprint(): string
    {
        $members = $this->thumbprintMembers;
        ksort($members, SORT_STRING);

        return Base64Url::encode(hash('sha256', json_encode($members, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), true));
    }

    private function isEd25519(): bool
    {
        return $this->keyType === 'OKP' && $this->curve === 'Ed25519';
    }

    /** @param array<mixed> $jwk */
    private static function ec(array $jwk, ?string $keyId, ?Algorithm $algorithm): self
    {
        $curve = $jwk['crv'] ?? null;
        $length = match ($curve) {
            'P-256' => 32,
            'P-384' => 48,
            default => throw InvalidJose::key('unsupported curve'),
        };

        $x = self::member($jwk, 'x');
        $y = self::member($jwk, 'y');
        if (strlen(Base64Url::decode($x)) !== $length || strlen(Base64Url::decode($y)) !== $length) {
            throw InvalidJose::key('coordinate length');
        }

        $pem = Der::ecPublicKey($curve, Base64Url::decode($x), Base64Url::decode($y));
        // openssl checks that the point lies on the curve when it parses the key.
        if (openssl_pkey_get_public($pem) === false) {
            throw InvalidJose::key('point is not on the curve');
        }

        return new self('EC', $curve, $keyId, $algorithm, ['crv' => $curve, 'kty' => 'EC', 'x' => $x, 'y' => $y], $pem);
    }

    /** @param array<mixed> $jwk */
    private static function rsa(array $jwk, ?string $keyId, ?Algorithm $algorithm): self
    {
        $n = self::member($jwk, 'n');
        $e = self::member($jwk, 'e');
        $modulus = ltrim(Base64Url::decode($n), "\x00");
        $exponent = ltrim(Base64Url::decode($e), "\x00");

        if (strlen($modulus) * 8 < self::MIN_RSA_BITS) {
            throw InvalidJose::key('RSA modulus shorter than 2048 bits');
        }
        if ($exponent === '' || strlen($exponent) > 4) {
            throw InvalidJose::key('RSA exponent');
        }

        $pem = Der::rsaPublicKey($modulus, $exponent);
        if (openssl_pkey_get_public($pem) === false) {
            throw InvalidJose::key('RSA key does not parse');
        }

        return new self('RSA', null, $keyId, $algorithm, ['e' => $e, 'kty' => 'RSA', 'n' => $n], $pem);
    }

    /** @param array<mixed> $jwk */
    private static function okp(array $jwk, ?string $keyId, ?Algorithm $algorithm): self
    {
        if (($jwk['crv'] ?? null) !== 'Ed25519') {
            throw InvalidJose::key('unsupported curve');
        }

        $x = self::member($jwk, 'x');
        $material = Base64Url::decode($x);
        if (strlen($material) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw InvalidJose::key('Ed25519 key length');
        }

        return new self('OKP', 'Ed25519', $keyId, $algorithm, ['crv' => 'Ed25519', 'kty' => 'OKP', 'x' => $x], $material);
    }

    /** @param array<mixed> $jwk */
    private static function member(array $jwk, string $name): string
    {
        $value = $jwk[$name] ?? null;
        if (!is_string($value) || $value === '') {
            throw InvalidJose::key('missing ' . $name);
        }

        return $value;
    }
}
