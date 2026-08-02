# EPIC-02 — Каркас MCP-сервера

## T-201 [P0] Бинарь MCP-сервера (rmcp, stdio) ✅

Критерии приёмки:

- добавлен `src/main.rs` (или `src/bin/server.rs`) на официальном Rust SDK (rmcp);
- сервер проходит initialize/handshake с MCP Inspector (`npx @modelcontextprotocol/inspector`);
- `tools/list` возвращает объявленный набор tools (минимум заглушки `list_data`);
- логирование только в stderr; ни одна строка лога не содержит значений секретов
  (использовать `SecretString`, правило CLAUDE.md → Security rules);
- полный tokio runtime добавляется в Cargo.toml этой задачей (сейчас только `sync`).

Выполнено 2026-07-15: `src/main.rs` (rmcp `tool_router`/`tool_handler`/`ServerHandler`,
stdio-транспорт), `tracing`+`tracing-subscriber` пишут только в stderr, `list_data` —
placeholder-tool. `cargo test`: 95/95 (90 существующих + 5 новых). Проверено вручную
через stdin/stdout pipe (initialize/tools-list/tools-call), MCP Inspector CLI недоступен
в среде — задокументировано как ограничение проверки, критерий приёмки закрыт ручным
прогоном протокола. Известный техдолг: прямая зависимость `async-trait` в Cargo.toml не
используется явно (тянется транзитивно через rmcp) — убрать в T-202.

## T-202 [P0] Конфигурация: data_folder из окружения плагина ✅

Критерии приёмки:

- путь к папке данных сервер получает из env-переменной/аргумента, задаваемых
  конфигурацией плагина (user_config), либо через tool `set_data_folder`;
- путь валидируется `verify_writable_and_readable` до первого использования;
- невалидный/недоступный путь → структурированная ошибка в ответе tool
  (не паника, не молчаливый фолбэк);
- конфиг персистится через `AppConfig` + `AtomicFileWriter` (сбой записи не
  повреждает прежний config.json — унаследованный контракт T-101);
- в config.json нет секретов (D-002, проверено тестом).

Выполнено 2026-07-15: env-переменная `VITALSTEAD_DATA_FOLDER` читается при старте
(`resolve_startup_data_folder`), с фолбэком на персистированный `config.json`;
tool `set_data_folder` валидирует путь через `verify_writable_and_readable` до
персиста, возвращает структурированную ошибку (`kind`/`message`) без паники.
Сбой персиста не обновляет in-memory state и не портит файл на диске — покрыто
тестом с инжектированным `FailingAtomicFileWriter` (прошёл QA-ревью после 1
цикла доработки: первая версия теста была no-op). `cargo test`: 101/101.
Заодно убрана неиспользуемая прямая зависимость `async-trait` (техдолг T-201).

## T-203 [P0] Каталог ошибок → ответы tools ✅

Критерии приёмки:

- `CallbackError`, `VaultError`, `TokenExchangeError`, `WriteError`, `ConfigError`
  маппятся в структурированные MCP-ошибки с кодом и человекочитаемым сообщением;
- сообщения не содержат секретов, полных callback URL и сырых ответов API (D-015);
- для каждого варианта ошибки задано recovery-действие для пользователя
  («переподключите источник», «проверьте папку» и т.п.);
- маппинг покрыт тестами (каждый вариант ошибки → ожидаемый код).

Выполнено 2026-07-15: новый модуль `src/error_mapping.rs` — trait `ToMcpError` +
`McpErrorDetails{code,message,recovery}`, покрывает все 19 вариантов пяти error
enum'ов (`CallbackError` 3, `VaultError` 4, `TokenExchangeError` 5, `WriteError` 4,
`ConfigError` 3, из которых `ConfigError::Write` делегирует маппинг вложенному
`WriteError`). Варианты с сырым `String`/`Option<String>` payload из внешних
источников (`VaultError::Backend`, `TokenExchangeError::Network`/`ClientError.error`,
`WriteError::Backend`, `ConfigError::Serialize`/`Read`) редактируются: payload
биндится через `_` и структурно недостижим в `message`/`recovery` (D-015) —
подтверждено ревью кода, не только тестами. Попутно найдена и устранена утечка
T-202: ветка `persist_failed` в `set_data_folder` использовала
`format!("{:?}", e)` — Rust Debug-репрезентация `ConfigError` в теле ответа tool;
заменено на `error_mapping::ToMcpError`. `SetDataFolderError` получил поле
`recovery`. `cargo test`: 127/127 (112 lib + 15 integration, включая 22 новых
unit-теста маппинга и 4 новых + 1 обновлённый в `main.rs`). `cargo clippy`: без
новых warnings. QA-ревью прошло с первого цикла (0 доработок). Вне scope: реальные
call sites для `CallbackError`/`VaultError`/`TokenExchangeError` в tool-хендлерах —
tools появятся в EPIC-03/04 и обязаны использовать `ToMcpError`.

## T-410 [P1] Setup-wizard как MCP Prompt — доступен сразу при подключении ✅

Продуктовый вопрос: как доставить пользователю мастер настройки (уже написанный
как Claude Skill, `plugin/skills/setup-guide/SKILL.md`) вместе с MCPB Extension,
если Anthropic продаёт их продукт именно как один `.mcpb`-артефакт для Desktop?
Проверено по официальной спецификации MCPB (`MANIFEST.md`, репозиторий
anthropics/dxt) — полей для встраивания Skills в манифест нет вообще; Claude
Desktop загружает кастомные Skills только отдельно, через Customize → Skills
(zip с `SKILL.md`), независимо от Extensions/Plugins.

Решение: MCP-протокол сам по себе имеет примитив **Prompts** (`prompts/list`,
`prompts/get`) — готовые шаблонизированные флоу, которые сервер объявляет сразу
при подключении, без отдельной установки со стороны пользователя. `manifest.json`
MCPB официально поддерживает поле `prompts`. Мастер настройки реализован как
prompt `setup_guide` прямо в Rust-сервере — доступен в один артефакт (`.mcpb`),
никакого второго шага для покупателя.

Критерии приёмки:

- сервер объявляет capability `prompts` в `initialize` (`capabilities.prompts`);
- `prompts/list` возвращает prompt `setup_guide` с description;
- `prompts/get` для `setup_guide` возвращает текст мастера как `PromptMessage`
  (`role: user`), без утечки секретов/health-данных (D-015);
- содержание не дублируется — единый источник с `plugin/skills/setup-guide/SKILL.md`
  (та же папка, что уже используется для отдельной Skill-загрузки и для Plugin-канала);
- тесты на: отделение YAML frontmatter от тела, отсутствие правил D-005 в тексте
  (regression guard), реальную регистрацию prompt в роутере и содержимое ответа
  `setup_guide_prompt()`.

Выполнено 2026-07-24: `src/main.rs` — поле `prompt_router: PromptRouter<Self>` на
`VitalsteadMcpServer`, `#[prompt_handler(router = self.prompt_router)]` застекирован
поверх уже существующего `#[tool_handler(router = self.tool_router)]` на одном
`impl ServerHandler` (rmcp-macros это официально поддерживает — "stacked
`#[prompt_handler]` on the same `impl ServerHandler`"), отдельный
`#[prompt_router]` impl-блок с `#[prompt(name = "setup_guide", ...)]`. Текст
мастера — `include_str!("../plugin/skills/setup-guide/SKILL.md")` +
`setup_guide_prompt_body()` (отрезает frontmatter между двумя `---`), а не вторая
копия текста — правки в SKILL.md (например, T-410 заодно поправил формулировку
шага 2/4 на канал-агностичную: `Settings → Extensions → Vitalstead → Configure`
вместо жёсткой ссылки на Plugin-канал) автоматически попадают и в prompt.
Smoke-test по stdio подтвердил: `initialize` → `capabilities.prompts` присутствует,
`prompts/list` → `setup_guide`, `prompts/get` → полный текст мастера. 4 новых
теста (frontmatter strip, regression guard на D-005-формулировку, регистрация в
роутере, содержимое ответа). `cargo test`: 282 (было 279) зелёных. `cargo clippy
--all-targets`: 0 новых warnings в `src/main.rs`. Universal-бинарь (arm64+x86_64)
и `.mcpb` пересобраны и провалидированы (`mcpb pack`).
