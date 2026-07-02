<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

final class Request
{
    private array $headersLower;
    private array $body;

    public function __construct(
        public readonly string $method,
        public readonly string $path,
        private array $query = [],
        array $headers = [],
        public readonly string $rawBody = '',
        private array $cookies = [],
        public readonly string $ip = '',
    ) {
        $this->headersLower = [];
        foreach ($headers as $k => $v) {
            $this->headersLower[strtolower($k)] = $v;
        }
        $decoded = json_decode($rawBody, true);
        $this->body = is_array($decoded) ? $decoded : [];
    }

    public static function fromGlobals(): self
    {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        return new self(
            method: $_SERVER['REQUEST_METHOD'] ?? 'GET',
            path: $path,
            query: $_GET,
            headers: $headers,
            rawBody: file_get_contents('php://input') ?: '',
            cookies: $_COOKIE,
            ip: self::clientIp(),
        );
    }

    private static function clientIp(): string
    {
        // Trust X-Forwarded-For only behind a known proxy in prod; here take first hop.
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') return trim(explode(',', $xff)[0]);
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public function query(string $k, ?string $default = null): ?string
    { return isset($this->query[$k]) ? (string) $this->query[$k] : $default; }

    public function input(string $k, mixed $default = null): mixed
    { return $this->body[$k] ?? $default; }

    public function allInput(): array { return $this->body; }

    public function header(string $k, ?string $default = null): ?string
    { return $this->headersLower[strtolower($k)] ?? $default; }

    public function cookie(string $k, ?string $default = null): ?string
    { return $this->cookies[$k] ?? $default; }

    public function bearerToken(): ?string
    {
        $h = $this->header('authorization', '');
        return (stripos($h, 'bearer ') === 0) ? substr($h, 7) : null;
    }

    public function wantsCookies(): bool { return $this->query('cookie') === 'true'; }

    public function isUnsafeMethod(): bool
    { return in_array($this->method, ['POST','PUT','PATCH','DELETE'], true); }
}
