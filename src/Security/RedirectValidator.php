<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

/**
 * Open-redirect defense for the verify/OAuth flows. Every caller-supplied
 * redirect target is resolved against SITE_URL + URI_ALLOW_LIST; anything that
 * doesn't match (foreign origin, javascript:/data: scheme, scheme-relative
 * //host, host-suffix tricks) falls back to SITE_URL. Allow-list entries ending
 * in '*' are full-URL prefix matches; other entries must match exactly.
 */
final class RedirectValidator
{
    /** @param string[] $allowList */
    public function __construct(
        private ?string $siteUrl,
        private array $allowList = [],
    ) {}

    public function resolve(?string $requested): string
    {
        $fallback = (string) $this->siteUrl;

        if ($requested === null || $requested === '') {
            return $fallback;
        }
        if (!$this->isHttpUrl($requested)) {
            return $fallback;
        }

        $candidates = $this->allowList;
        if ($fallback !== '') {
            $candidates[] = $fallback;
        }

        $normalizedRequest = $this->normalize($requested);
        foreach ($candidates as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (str_ends_with($entry, '*')) {
                $prefix = $this->normalize(substr($entry, 0, -1));
                if ($prefix !== '' && str_starts_with($normalizedRequest, $prefix)) {
                    return $requested;
                }
            } elseif ($normalizedRequest === $this->normalize($entry)) {
                return $requested;
            }
        }

        return $fallback;
    }

    /** Absolute http(s) URL with a real host — rejects //host and exotic schemes. */
    private function isHttpUrl(string $url): bool
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($scheme)
            && in_array(strtolower($scheme), ['http', 'https'], true)
            && is_string($host)
            && $host !== '';
    }

    /**
     * Lowercase the scheme://host[:port] part so origin comparison is
     * case-insensitive while the path/query keep their case.
     */
    private function normalize(string $url): string
    {
        return preg_replace_callback(
            '#^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*#',
            static fn(array $m): string => strtolower($m[0]),
            $url,
        ) ?? $url;
    }
}
