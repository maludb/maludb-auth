<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Maludb\Auth\App;
use Maludb\Auth\Http\Request;

App::boot()->handle(Request::fromGlobals())->send();
