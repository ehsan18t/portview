@echo off
REM portview — Pre-push hook (Windows batch version)
REM Runs the full quality gate before pushing to remote.
REM This mirrors the CI checks so issues are caught locally before a PR.
REM
REM Install: copy this file to .git\hooks\pre-push
REM          (remove the .bat extension when copying)

echo ======================================
echo   portview Pre-Push Quality Gate
echo ======================================
echo.

REM Gate 1: Formatting
echo -^> [1/7] Checking formatting...
cargo fmt --all -- --check
if %ERRORLEVEL% neq 0 (
    echo.
    echo X FORMATTING FAILED
    echo   Run: cargo fmt
    echo   Then try pushing again.
    exit /b 1
)
echo   OK Formatting

REM Gate 2: Clippy
echo -^> [2/7] Running clippy...
cargo clippy --all-targets -- -D warnings
if %ERRORLEVEL% neq 0 (
    echo.
    echo X CLIPPY FAILED
    echo   Fix the lint errors above, then try pushing again.
    exit /b 1
)
echo   OK Clippy

REM Gate 3: Tests
echo -^> [3/7] Running tests...
cargo test --all-targets
if %ERRORLEVEL% neq 0 (
    echo.
    echo X TESTS FAILED
    echo   Fix the failing tests, then try pushing again.
    exit /b 1
)
echo   OK Tests

REM Gate 4: Benchmarks
echo -^> [4/7] Compiling benchmarks...
cargo bench --no-run
if %ERRORLEVEL% neq 0 (
    echo.
    echo X BENCHMARK COMPILE FAILED
    echo   Fix the benchmark build errors, then try pushing again.
    exit /b 1
)
echo   OK Benchmarks

REM Gate 5: Debug build
echo -^> [5/7] Building debug binary...
cargo build
if %ERRORLEVEL% neq 0 (
    echo.
    echo X DEBUG BUILD FAILED
    echo   Fix the build errors, then try pushing again.
    exit /b 1
)
echo   OK Debug build

REM Gate 6: Documentation
echo -^> [6/7] Building docs...
set "RUSTDOCFLAGS=-D warnings -D rustdoc::bare_urls -D rustdoc::invalid_rust_codeblocks -D rustdoc::private_intra_doc_links -D rustdoc::unescaped_backticks"
cargo doc --no-deps
if %ERRORLEVEL% neq 0 (
    echo.
    echo X DOCUMENTATION BUILD FAILED
    echo   Fix the doc errors, then try pushing again.
    exit /b 1
)
echo   OK Docs

REM Gate 7: Dependency audit (optional)
echo -^> [7/7] Auditing dependencies...
where cargo-deny >nul 2>nul
if %ERRORLEVEL% equ 0 (
    cargo deny check 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   Warning: First attempt failed, clearing advisory-db cache...
        if exist "%USERPROFILE%\.cargo\advisory-dbs" rd /s /q "%USERPROFILE%\.cargo\advisory-dbs"
        if exist "%USERPROFILE%\.cargo\advisory-db" rd /s /q "%USERPROFILE%\.cargo\advisory-db"
        cargo deny check 2>nul
        if %ERRORLEVEL% neq 0 (
            echo.
            echo   WARNING: DEPENDENCY AUDIT FAILED ^(non-blocking^)
            echo   CI will enforce this check on the pull request.
        ) else (
            echo   OK Dependency audit ^(after cache clear^)
        )
    ) else (
        echo   OK Dependency audit
    )
) else (
    echo   SKIP cargo-deny not installed ^(install: cargo install cargo-deny^)
)

echo.
echo All quality gates passed. Pushing...
