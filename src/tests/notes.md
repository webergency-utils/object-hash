# Testing Knowledge Base

## Rules

* **AAA Pattern (Arrange, Act, Assert)**: Separate each phase of the test with visual whitespace.
* **Test Isolation**: Instantiate fresh objects in each test or inside `beforeEach`. Never mutate shared variables across test blocks.
* **Coverage Targets**: Ensure all branch conditions (if/else, throw paths, and default fallbacks) are explicitly covered.

## Anti-Patterns

* Avoid relying on Node-only globals (`Buffer`, `require`) when testing browser fallback behavior; restore modified globals inside `finally` blocks.
* Do not assert legacy unframed representations (`Symbol(a)`, `Uint8Array(1,2,3)`) that permit delimiter-injection collisions.

## Mocking Conventions

* Use `vi.fn()` for callback verification where simple function spies suffice.
* When simulating browser/non-Node environments (`Buffer` or `process.getBuiltinModule` unavailable), save and restore original globals in `try`/`finally` blocks.
* When smoke-testing built bundle outputs (`dist/hash.js` ESM or `fuzz_hash.cjs` against `dist/hash.cjs`), invoke them in a child process (`execFileSync`) so V8 sourcemap coverage on `src/` remains unpolluted.
