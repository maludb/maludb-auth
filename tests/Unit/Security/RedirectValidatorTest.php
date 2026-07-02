<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\RedirectValidator;
use PHPUnit\Framework\TestCase;

final class RedirectValidatorTest extends TestCase
{
    private function validator(): RedirectValidator
    {
        return new RedirectValidator(
            'http://localhost:3000',
            ['http://localhost:3000/*', 'https://app.example.com/auth/done'],
        );
    }

    public function test_null_or_empty_falls_back_to_site_url(): void
    {
        $v = $this->validator();
        $this->assertSame('http://localhost:3000', $v->resolve(null));
        $this->assertSame('http://localhost:3000', $v->resolve(''));
    }

    public function test_exact_site_url_passes(): void
    {
        $this->assertSame(
            'http://localhost:3000',
            $this->validator()->resolve('http://localhost:3000'),
        );
    }

    public function test_wildcard_prefix_entry_passes(): void
    {
        $this->assertSame(
            'http://localhost:3000/reset?step=2',
            $this->validator()->resolve('http://localhost:3000/reset?step=2'),
        );
    }

    public function test_exact_allow_list_entry_passes_and_near_miss_fails(): void
    {
        $v = $this->validator();
        $this->assertSame(
            'https://app.example.com/auth/done',
            $v->resolve('https://app.example.com/auth/done'),
        );
        // Exact entry — a longer URL under it is NOT allowed.
        $this->assertSame(
            'http://localhost:3000',
            $v->resolve('https://app.example.com/auth/done/extra'),
        );
    }

    public function test_foreign_origin_falls_back(): void
    {
        $this->assertSame(
            'http://localhost:3000',
            $this->validator()->resolve('https://evil.com/phish'),
        );
    }

    public function test_host_suffix_trick_falls_back(): void
    {
        // Wildcard is a PREFIX match on the full URL; the '*' entry is
        // 'http://localhost:3000/*' so the attacker URL must fail because the
        // origin differs before the wildcard.
        $this->assertSame(
            'http://localhost:3000',
            $this->validator()->resolve('http://localhost:3000.evil.com/x'),
        );
    }

    public function test_host_only_wildcard_entry_rejects_suffixed_attacker_host(): void
    {
        // The dangerous form: a '*' entry that ends at the host with no path
        // separator. A raw prefix compare would accept the attacker's host.
        $v = new RedirectValidator('http://localhost:3000', ['https://app.example.com*']);

        $this->assertSame(
            'http://localhost:3000',
            $v->resolve('https://app.example.com.evil.com/phish'),
        );
        // The legitimate origin still passes.
        $this->assertSame(
            'https://app.example.com/callback',
            $v->resolve('https://app.example.com/callback'),
        );
    }

    public function test_wildcard_does_not_match_different_port(): void
    {
        $v = new RedirectValidator('http://localhost:3000', ['http://localhost:3000/*']);
        $this->assertSame(
            'http://localhost:3000',
            $v->resolve('http://localhost:4000/x'),
        );
    }

    public function test_dangerous_schemes_fall_back(): void
    {
        $v = $this->validator();
        $this->assertSame('http://localhost:3000', $v->resolve('javascript:alert(1)'));
        $this->assertSame('http://localhost:3000', $v->resolve('//evil.com'));
        $this->assertSame('http://localhost:3000', $v->resolve('data:text/html,x'));
    }

    public function test_scheme_and_host_compare_case_insensitively(): void
    {
        $this->assertSame(
            'HTTP://LOCALHOST:3000/ok',
            $this->validator()->resolve('HTTP://LOCALHOST:3000/ok'),
        );
    }
}
