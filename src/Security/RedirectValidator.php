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
        $reqOrigin = $this->originOf($requested);
        if ($reqOrigin === null) {
            return $fallback; // rejects //host, javascript:, data:, missing host
        }

        $candidates = $this->allowList;
        if ($fallback !== '') {
            $candidates[] = $fallback;
        }

        $reqRemainder = $this->remainderOf($requested);
        foreach ($candidates as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }

            $isWildcard = str_ends_with($entry, '*');
            $base = $isWildcard ? substr($entry, 0, -1) : $entry;

            // Origin (scheme://host:port) MUST match exactly — a prefix compare
            // on the whole URL would let 'https://app.example.com*' be satisfied
            // by 'https://app.example.com.evil.com'. Only the PATH is prefixed.
            $entryOrigin = $this->originOf($base);
            if ($entryOrigin === null || $entryOrigin !== $reqOrigin) {
                continue;
            }

            $entryRemainder = $this->remainderOf($base);
            if ($isWildcard) {
                if (str_starts_with($reqRemainder, $entryRemainder)) {
                    return $requested;
                }
            } elseif ($reqRemainder === $entryRemainder) {
                return $requested;
            }
        }

        return $fallback;
    }

    /**
     * Lowercased scheme://host[:port] for an absolute http(s) URL, or null if
     * the URL has no http(s) scheme or no host (rejects //host, javascript:,
     * data:, mailto:, relative URLs).
     */
    private function originOf(string $url): ?string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true) || $parts['host'] === '') {
            return null;
        }
        $origin = $scheme . '://' . strtolower($parts['host']);
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        return $origin;
    }

    /** Everything after the origin (path + query + fragment), case-preserved. */
    private function remainderOf(string $url): string
    {
        $stripped = preg_replace('~^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*~', '', $url, 1);

        return $stripped ?? '';
    }
}
