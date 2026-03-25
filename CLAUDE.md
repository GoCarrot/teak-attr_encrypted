# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

teak-attr_encrypted is a Ruby gem that provides a DSL for transparent envelope encryption/decryption of attributes on any class (primarily ORM models). It uses a Key Encryption Key (KEK) provider pattern where data keys are generated per-encryption and themselves encrypted by the KEK.

## Commands

- **Install dependencies:** `bundle install`
- **Run all tests:** `bundle exec rake spec`
- **Run a single test file:** `bundle exec rspec spec/teak/encryptor_spec.rb`
- **Run a single test by line:** `bundle exec rspec spec/teak/encryptor_spec.rb:42`
- **Interactive console:** `bin/console`

## Architecture

The gem implements envelope encryption with a two-tier key hierarchy:

- **`Teak::AttrEncrypted`** — Entry module. `include` it in a class to get the `attr_encrypted` DSL. Holds the global `default_kek_provider`.
- **`DSL`** (`lib/teak/attr_encrypted/dsl.rb`) — Defines `attr_encrypted` class method. For each encrypted attribute, it creates a getter/setter pair that delegates to an `Encryptor` instance. Supports `context:` (symbol, proc, or literal) as additional authenticated data.
- **`Encryptor`** (`lib/teak/attr_encrypted/encryptor.rb`) — Handles AES-256-GCM encrypt/decrypt. Produces versioned envelopes: a version char prefix + Base64-encoded MessagePack blob containing IV, auth tag, encrypted data key, and ciphertext.
- **KEK Providers** (`lib/teak/attr_encrypted/kek_provider/`) — Generate and decrypt data keys:
  - `Base` — Abstract base with an `id` accessor.
  - `AES` — Local AES-256-GCM key wrapping. Intended for dev/test only.
  - `AwsKMS` — Production provider using AWS KMS `GenerateDataKey`/`Decrypt` for envelope encryption.
- **`Testing`** (`lib/teak/attr_encrypted/testing.rb`) — Test helpers that prepend onto `Encryptor` to allow/deny encryption contexts in test scopes. Provides `RSpecHelpers` module.

## Key Details

- Ruby 3.1.4 (`.ruby-version`), gemset managed via `.ruby-gemset`
- Only runtime dependency: `msgpack ~> 1.7`
- Test dependencies: `rspec`, `simplecov` (branch coverage enabled), `aws-sdk-kms`
- RSpec configured with `disable_monkey_patching!` and `expect` syntax only
- Envelope format is versioned (currently version `'1'`) to allow future format changes
