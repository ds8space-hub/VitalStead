# EPIC-01 — Перенос ядра из родительского проекта

## T-101 [P0] Перенести Rust-ядро без Tauri-зависимостей ✅

Выполнено 2026-07-15. Перенесено из `../Control your data/src-tauri/src`
(коммит f7cc4da + незакоммиченный WIP T-203):

- `core/` (oauth, csv, sync, security), `adapters/`, `platform/macos/`, `config.rs`;
- удалена диалоговая реализация `MacFilePicker` (tauri-plugin-dialog); трейт
  `FilePicker`, `PickerError` и `verify_writable_and_readable` сохранены,
  валидация сделана `pub` — её вызывает обработчик конфигурации;
- `lib.rs` переписан: composition root без `tauri::AppHandle`;
- починена компиляция тестов WIP-кода T-203 (`refresh.rs` в родителе не компилировался):
  добавлены `PartialEq` для `RefreshOutcome`/`RefreshError`/`VaultError`, `Clone` для
  `RefreshRequest`, мок `refresh_token` разворачивает вложенный `Result`.

Критерии приёмки (проверены):

- `cargo test` зелёный: 90/90, набор тестов идентичен родительскому дереву;
- ни одной ссылки на `tauri`/`tauri_plugin_dialog` в `src/`;
- логика ядра не менялась (только derive'ы и мок, см. выше).

## T-102 [P1] QA-ревью перенесённого refresh-оркестратора (родительский T-203)

`core/oauth/refresh.rs` — WIP родительского проекта, не проходивший там QA-ревью.
Дефекты компиляции тестов (см. T-101) — сигнал, что код не прогонялся целиком.

Критерии приёмки:

- ревью-диф оркестратора против правил refresh родительского
  `credentials-and-security.md` (backoff-таблицы, invalid_grant, ротация,
  исключение параллельного refresh);
- каждое расхождение оформлено задачей в этом эпике или исправлено на месте;
- предупреждения компилятора в `platform/macos/credential_vault.rs`
  (unused variable/mut) устранены или обоснованы комментарием.

## T-103 [P2] CI: cargo test + clippy на каждый push

Критерии приёмки:

- GitHub Actions (или эквивалент) запускает `cargo test` и `cargo clippy -- -D warnings`
  на macOS runner;
- секреты/фикстуры в CI не используются (тесты герметичны уже сейчас);
- бейдж статуса в README.
