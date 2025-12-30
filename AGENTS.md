# Repository Guidelines

## Project Structure & Module Organization
This is a single-module Maven library. Runtime sources live in `src/main/java/org/jose4j/**`, organized by JOSE concern (keys, jws, jwe, jwk, lang). Tests belong in `src/test/java` mirroring the package being exercised, while shared fixtures such as sample JWKS files go in `src/test/resources`. Maven outputs (`target/`) should stay untracked; artifacts of interest are the shaded and plain JARs emitted during packaging.

## Build, Test, and Development Commands
- `mvn clean install` — default workflow that compiles against Java 8, executes the full JUnit suite, and produces the distributable JAR under `target/`.
- `mvn test -Dtest=ClassNameTest` — runs focused unit tests while leaving the previous build untouched.
- `mvn package -DskipTests` — compiles and assembles quickly for exploratory smoke checks; never use this for release validation.
- `mvn -P release deploy` — activates the release profile (GPG signing, source/javadoc bundles) used by the Sonatype pipeline; requires configured credentials.

## Coding Style & Naming Conventions
Use four-space indentation, brace-on-newline formatting, and descriptive enum/constant names consistent with existing classes (e.g., `KeyPersuasion`). Keep packages under `org.jose4j` and follow the `CamelCase` class convention with `UpperCamelCase` enums and `lowerCamelCase` methods/fields. Favor immutable inputs (`final` where practical) and rely on SLF4J’s parameterized logging (`log.debug("...", value)`). Public APIs require Javadoc explaining how they fit into the JOSE workflows.

## Testing Guidelines
JUnit 4 is the primary framework, with Mockito and BouncyCastle available for cryptographic doubles. Name tests `<Feature>Test.java`, locate them beside the class under test, and keep fixture data in resources with clear identifiers (`src/test/resources/jwks/valid.json`). Cover both positive JOSE flows and failure modes (key resolution errors, malformed tokens). Before opening a PR, run `mvn clean test` to ensure deterministic cryptographic behavior.

## Commit & Pull Request Guidelines
Git history favors short imperative summaries (“Update slf4j dependency”). Keep commits focused on a single concern, include rationale in the body if behavior changes, and reference issues when applicable (`Fix #123`). PRs should state motivation, summarize functional impact, list verification steps, and attach any new vector files or console output that proves compatibility with JOSE clients. Screenshots are unnecessary; JSON snippets or command transcripts are preferred.

## Security & Configuration Tips
Never commit private keys, keystores, or credentials—use environment variables or the Maven settings.xml credential store. Refresh dependencies thoughtfully and note security-related upgrades explicitly. When working on release automation, ensure local GPG keys match the ones configured for Sonatype, and vet any new cryptographic provider settings against the JOSE specifications before merging.
