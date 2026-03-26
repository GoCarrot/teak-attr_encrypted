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

- Ruby 3.2.2 (`.ruby-version`), gemset managed via `.ruby-gemset`
- Only runtime dependency: `msgpack ~> 1.7`
- Test dependencies: `rspec`, `simplecov` (branch coverage enabled), `aws-sdk-kms`
- RSpec configured with `disable_monkey_patching!` and `expect` syntax only
- Envelope format is versioned (currently version `'1'`) to allow future format changes


## 📋 Commit Requirements (ALL Work - Features, Docs, Refactoring, Everything)

### Every Commit Must Capture Human-Claude Interaction

**The commit template below is MANDATORY for ALL commits** - documentation changes, refactoring, bug fixes, features, CLAUDE.md updates, everything. This captures how humans effectively guide Claude.

### When to Commit
Only commit when:
- ✅ Tests pass (if applicable)
- ✅ Human explicitly requests commit OR
- ✅ Reached major milestone

Never commit:
- ❌ Without capturing full interaction log
- ❌ With failing tests or lint errors
- ❌ "Proactively" without meeting above criteria

### Commit Checklist
Before ANY commit:
- [ ] Did I run `rake lint` and fix any issues?
- [ ] Did I run tests (`rspec`) if applicable?
- [ ] Did I search for existing patterns before writing code?
- [ ] Did I document any NEW problem/solution in CLAUDE.md?
- [ ] Am I solving a genuinely new problem? (Rare!)
- [ ] **Did I capture VERBATIM human-Claude interactions in commit message?**

### MANDATORY: Output Before EVERY Commit (All Work Types, Including Amends!)
You MUST output exactly (even for `git commit --amend`):
```
📝 COMMIT READY CHECK:
☑️ Lint clean: [YES/NO/NA - only if code changed]
☑️ Tests pass: [YES/NO/NA - only if code changed]
☑️ Tested in CLI: [YES/NO/NA - only if CLI code changed]
☑️ Documented new patterns: [YES/NO/NA - only if applicable]
☑️ ALL prompts since last commit captured: [YES - X prompts captured VERBATIM]

[If ANY are NO: "❌ NOT ready - need to: (list required actions)"]
[If ALL are YES/NA: "✅ Ready to commit with COMPLETE Human-Claude interaction log."]
```

When ready, commit your work with the human-Claude interaction log.

**Note on Amending**: `git commit --amend` still requires the full checklist - code may have changed since original commit.

**Universal Commit Message Template** (USE FOR EVERY COMMIT - docs, refactoring, features, EVERYTHING):
```bash
# First, check what you modified:
git status
# Then add YOUR specific changes (not everything):
git add [specific files you changed]
# For multiple files:
git add file1.js file2.rb CLAUDE.md
# Commit with interaction log:
git commit -m "$(cat <<'EOF'
Brief description of what was done

[Technical changes made]

## Human-Claude Interaction Log

### Human prompts (VERBATIM - include typos, informal language, COMPLETE text):
**Include EVERY prompt since last commit - even short ones, corrections, clarifications**
1. "[Copy-paste ENTIRE first prompt since last commit]"
   → Claude: [What Claude did in response]

2. "[Copy-paste ENTIRE second prompt - including [Request interrupted] if present]"
   → Claude: [How Claude adjusted]

[Continue numbering ALL prompts - don't skip any or judge importance]

### Key decisions made:
- Human guided: [specific guidance provided]
- Claude discovered: [patterns found]

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```
**Note**: Avoid `git add -A` when multiple Claudes work in parallel - add only YOUR files.

## GitHub Operations and Pull Request Creation

### Team GitHub Usernames
- Mark → **@blamfantastico**
- Alex → **@AlexSc**
- Jon → **@MrJoy**

### Creating Pull Requests with Proper Escaping

When creating pull requests using `gh pr create`, **ALWAYS use heredoc syntax** to ensure proper escaping of all special characters in the PR body.

**Critical Requirements:**

- **ALWAYS use heredoc (`cat <<'EOF'...EOF`)** for the `--body` parameter to ensure proper escaping of all special characters (quotes, backticks, dollar signs, parentheses, brackets, etc.)
- The single quotes around `'EOF'` prevent variable expansion within the heredoc
- This pattern safely handles any text content without manual escaping
- Never attempt to manually escape characters - let the heredoc handle it

**Correct PR Creation Example:**

```bash
# IMPORTANT: Always use heredoc syntax for --body to properly escape special characters
gh pr create --title "the pr title" --body "$(cat <<'EOF'
## Summary
- Feature implementation with special chars like $, `, ", ', [], ()
- Bug fixes for edge cases

## Test plan
- [ ] Unit tests pass
- [ ] Integration tests complete
- [ ] Manual testing done

## Notes
Any text here is safe, including: "quotes", `backticks`, $variables,
[brackets], (parentheses), and other special characters!

🤖 Generated with [Claude Code](https://claude.ai/code)
EOF
)"
```

**Why Heredocs Solve Escaping Issues:**

1. The heredoc delimiter (`'EOF'`) with single quotes prevents shell expansion
2. All content between delimiters is treated as literal text
3. No need to escape individual characters
4. Handles multi-line content naturally
5. Same pattern used successfully for commit messages

### Other GitHub CLI Operations

- View PR comments: `gh pr view <number> --comments`
- Check PR status: `gh pr status`
- List PRs: `gh pr list`
- View PR diff: `gh pr diff <number>`

**Important:** Never update git config or push to remote unless explicitly requested by the user.
