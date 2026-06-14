# Contributing

Thanks for helping improve **oihana/php-auth**.

## Requirements

- **PHP 8.4+**
- **Composer**
- **Xdebug** or **PCOV** — only needed to measure test coverage (see below).

## Setup

```shell
git clone https://github.com/BcommeBois/oihana-php-auth.git
cd oihana-php-auth
composer install
```

## Tests & coverage

```shell
composer test            # run the unit suite (PHPUnit, strict mode)
composer coverage        # suite + coverage report (text + Clover + HTML under build/coverage/)
composer coverage:md     # regenerate build/coverage/COVERAGE.md, a readable Markdown summary
```

The suite runs in **strict mode**: warnings, risky tests (no assertion), and
skipped tests all fail the run. A test that checks nothing protects nothing.

Coverage output lives under `build/coverage/` and is **gitignored** — it is a
snapshot that goes stale at the next commit, so we regenerate it on demand
rather than committing it. `composer coverage:md` also keeps a small local
trend log (`build/coverage/history.json`) so each run shows the delta since the
previous one.

A short reminder of the testing philosophy:

- Coverage measures which lines ran, **not** which behaviours are verified —
  100% coverage is not zero bugs.
- When you discover a surprising behaviour in existing code, **freeze it in a
  test** first. Do not change a public API's behaviour without discussing it:
  other libraries may rely on it.
- Test everything reachable; only annotate a line `@codeCoverageIgnore` when it
  is genuinely impossible to reach (e.g. a defensive guard the public surface
  cannot trigger).
