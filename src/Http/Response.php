<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(
        public int $status = 200,
        public string $body = '',
        public array $headers = [],
        public array $cookies = [],
    ) {}

    public static function json(mixed $data, int $status = 200): self
    {
        return new self(
            status: $status,
            body: json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            headers: ['Content-Type' => 'application/json'],
        );
    }

    public static function error(string $code, string $message, int $status): self
    {
        return self::json(['error' => $code, 'error_description' => $message], $status);
    }

    public static function redirect(string $url, int $status = 302): self
    {
        return new self(status: $status, headers: ['Location' => $url]);
    }

    public function withHeader(string $k, string $v): self
    {
        $this->headers[$k] = $v;
        return $this;
    }

    public function withCookie(string $name, string $value, array $options = []): self
    {
        $this->cookies[] = ['name' => $name, 'value' => $value, 'options' => $options + [
            'expires' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => false,
        ]];
        return $this;
    }

    public function withClearedCookie(string $name, string $path = '/'): self
    {
        return $this->withCookie($name, '', ['expires' => 0, 'path' => $path, 'maxage' => -1]);
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header("$k: $v");
        }
        foreach ($this->cookies as $c) {
            $o = $c['options'];
            setcookie($c['name'], $c['value'], [
                'expires' => $o['maxage'] ?? -1 === -1 ? ($o['expires'] ?? 0) : time() + ($o['maxage']),
                'path' => $o['path'], 'secure' => $o['secure'], 'httponly' => $o['httponly'],
                'samesite' => $o['samesite'],
            ]);
        }
        echo $this->body;
    }
}
