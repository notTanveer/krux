# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Krux is open-source Bitcoin signing device firmware targeting Kendryte K210 devices (M5StickV, Amigo, Dock, Yahboom, Cube, WonderMV, TZT, WonderK, Embed Fire). The firmware runs MicroPython on bare metal — memory is extremely constrained, so the codebase manually calls `gc.collect()` and uses `sys.modules.pop()` to unload modules after use.

## Development commands

```bash
# Install dependencies
poetry install

# Format
poetry run poe format

# Lint
poetry run poe lint

# Run all tests with coverage
poetry run poe test

# Run tests without coverage (faster)
poetry run poe test-simple

# Run a single test
poetry run pytest --cache-clear ./tests/pages/test_login.py -k 'test_load_key_from_hexadecimal'

# Run simulator (touch device, Amigo)
poetry install --all-extras
poetry run poe simulator
```

Build firmware (requires Docker):
```bash
./krux build maixpy_amigo
./krux flash maixpy_amigo
```

i18n workflow (always run when adding new `t()` calls):
```bash
poetry run poe i18n clean
poetry run poe i18n fill       # auto-translate missing strings
poetry run poe i18n validate
poetry run poe i18n bake       # compiles translations.py
```

Pre-commit check (what CI runs):
```bash
poetry run poe pre-commit
```

## Architecture

### Boot flow

`src/boot.py` is the entry point. It runs in order: splash screen → firmware update check → `tc_code_verification` → `login` → `home` → shutdown. Each phase lazy-imports its module and then explicitly unloads it with `sys.modules.pop()` to reclaim RAM.

### Context singleton

`src/krux/context.py` holds a single `ctx = Context()` instance shared across the entire app. It owns:
- `ctx.display` — LCD driver
- `ctx.input` — button/touch input
- `ctx.camera` — camera
- `ctx.wallet` — loaded `Wallet` (None when logged out)
- `ctx.power_manager` — battery/shutdown

### Device capabilities

`src/krux/kboard.py` holds a `kboard = KBoard()` singleton that reads `board.config` at startup to expose device-specific flags: `has_touchscreen`, `has_minimal_display`, `has_battery`, `has_encoder`, etc. Any code that branches on device type uses `kboard`, not raw `board` calls.

### Pages and menus

`src/krux/pages/__init__.py` defines two base classes:
- `Page` — base for every screen. Owns `self.ctx`. Provides helpers: `prompt()`, `flash_text()`, `capture_from_keypad()`, `display_qr_codes()`, `display_mnemonic()`.
- `Menu` — renders a scrollable list, handles button/touch navigation, calls item callbacks, and returns one of `MENU_CONTINUE / MENU_EXIT / MENU_SHUTDOWN / MENU_RESTART`.

Page subclasses live in:
- `src/krux/pages/` — login flow, mnemonic entry/backup, QR capture, encryption UI, tools, etc.
- `src/krux/pages/home_pages/` — post-login features (signing, addresses, BIP85, wallet descriptor, etc.)
- `src/krux/pages/new_mnemonic/` — entropy-based mnemonic generation

### Translations

All user-visible strings are wrapped in `t("...")` from `krux.krux_settings`. Translation files live in `i18n/translations/`. After adding or removing `t()` calls, run the i18n commands above before committing.

### Testing

Tests run on CPython and mock all MicroPython-specific modules (`lcd`, `Maix`, `board`, `machine`, `sensor`, `uos`, `ucryptolib`, etc.). The `mp_modules` fixture in `tests/conftest.py` installs these mocks via `monkeypatch`. `tests/shared_mocks.py` provides board configs for each device type (call `board_amigo()`, `board_m5stickv()`, etc. to configure the device under test).

## Branch / commit conventions

- Branch from `develop`; open PRs targeting `develop`. `main` is the latest release.
- Conventional commits are enforced: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `i18n`, `ci`, `chore`, `git`.
- Versioning follows CalVer (`YY.MM.MICRO`).
