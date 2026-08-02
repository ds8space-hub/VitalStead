# Архитектура

## Компоненты

```
Claude Desktop (или другой MCP-клиент)
│  plugin: skill + slash-команды + конфигурация MCP-сервера
│
│  MCP (stdio) — tool calls; секреты через эту границу не проходят (D-015)
▼
MCP-сервер (Rust-бинарь, rmcp)                       ← EPIC-02
├── Tool surface: connect_provider, sync_now, sync_provider,
│   list_data, query_data, import_garmin_zip,
│   disconnect_provider, delete_app_data              ← EPIC-02/05/06
├── core/oauth      — state machine, authorization, refresh-оркестратор
├── core/sync       — sync state, cursor
├── core/csv        — schema, parse/serialize, upsert, writer
├── core/security   — SecretString (защита от утечки в логи/Debug)
├── config          — AppConfig { data_folder }, атомарная запись
├── adapters        — трейты: CredentialVault, OAuthCallbackHandler,
│   TokenExchangeClient, AtomicFileWriter, FilePicker (валидация папки)
└── platform/macos  — Keychain (keyring), запуск браузера
        │                    │                     │
        ▼                    ▼                     ▼
   OS Keychain        API провайдеров       CSV-папка пользователя
```

Ядро (`core/`, `adapters/`, `config`) перенесено из родительского проекта без изменения
логики и не содержит `#[cfg(target_os)]` (D-011). Платформенные реализации выбираются
только в composition root (`lib.rs`).

## Граница доверия (D-015)

Модель взаимодействует с данными исключительно через tools. Через границу
«модель ⇄ сервер» проходят: параметры tools (пути, провайдер, диапазоны дат),
статусы операций, агрегаты/метаданные данных. Не проходят никогда: client secrets,
access/refresh tokens, authorization codes, полные callback URL, сырые ответы API.
Полные health-данные — только по явному запросу пользователя (T-603).

## OAuth: callback через localhost loopback

Отличие от родительского проекта: вместо deep-link (custom URI scheme + Info.plist)
callback принимает **временный HTTP-listener на 127.0.0.1** (T-301):

1. `connect_provider` → сервер генерирует `state` (uuid v4), поднимает listener на
   свободном порту, открывает системный браузер с authorization URL;
2. пользователь логинится на сайте провайдера (D-005), провайдер редиректит на
   `http://127.0.0.1:{port}/callback`;
3. listener валидирует `state`, гасится, отдаёт код через `CallbackReceiver`;
4. сервер меняет код на токены (T-303), сохраняет их в Keychain, отвечает модели
   статусом — без токенов.

Таймаут ожидания callback — 5 минут (унаследовано из контракта T-006 L104-106).
Повторное/просроченное предъявление callback отклоняется (pending-store, T-302).

## Контракт атомарности синка

Унаследован дословно: синк успешен только когда все страницы получены, данные
провалидированы, все CSV записаны и атомарно заменены (`AtomicFileWriter`:
temp + backup + rename), sync cursor персистирован. Сетевая ошибка не переводит
источник в `disconnected`; прежние CSV остаются доступными.

## Конфигурация вместо диалогов

UI-диалогов нет. `data_folder` приходит из конфигурации плагина/бандла (user_config)
или задаётся tool-вызовом; сервер валидирует его write-probe + read-probe
(`adapters::file_picker::verify_writable_and_readable`) перед использованием.
Путь к Garmin ZIP — аргумент `import_garmin_zip`. Трейт `FilePicker` сохранён для
будущего desktop-фасада; диалоговой реализации в этом репозитории нет.

## Упаковка (целевая структура, EPIC-07)

```
plugin/                          # Claude plugin (personal marketplace → Partners)
├── .claude-plugin/plugin.json   # манифест: имя, версия, компоненты
├── skills/setup-guide/SKILL.md  # бывший AI_SETUP_GUIDE (D-014): подключение,
│                                # интерпретация данных, запреты D-005/D-015
├── commands/                    # /connect, /sync, /import-garmin, /disconnect
└── .mcp.json                    # запуск локального бинаря сервера

mcpb/                            # MCPB-бандл для Claude Desktop (one-click)
└── manifest.json                # user_config: data_folder (directory),
                                 # client_id/client_secret (sensitive → Keychain),
                                 # server.type = binary
```

Каталоги создаются задачами EPIC-07, не заранее.

## Кросс-платформенная граница (уточнение D-011)

Платформонезависимо: коннекторы, OAuth state machine, refresh, sync engine,
CSV schema/mapping/upsert, sync state, каталог ошибок, tool surface.
За платформенными адаптерами: Keychain/Credential Manager (`CredentialVault`),
запуск браузера (`OAuthCallbackHandler::open_system_browser`), файловая атомарная
замена (`AtomicFileWriter`). Выпали из границы по сравнению с родителем: deep-link
(заменён loopback-listener'ом — он кросс-платформенный), диалог выбора папки
(заменён user_config), авто-апдейт (обновления доставляет marketplace/директория).

## Чеклист: добавление нового OAuth-провайдера

Основано на структуре `core/connectors/whoop/` (T-401, первый реализованный
коннектор). Каждый новый провайдер (Oura — T-402, и любые последующие)
создаёт СВОЙ модуль `core/connectors/<provider>/` — общее ядро (`core/csv`,
`core/oauth`, `core/sync`) не меняется.

### Файлы для создания (core/connectors/<provider>/)

- `mod.rs` — экспорт submodules (см. whoop/mod.rs как образец)
- `dto.rs` — response types провайдер-API (serde::Deserialize), без бизнес-логики
- `mapping.rs` — DTO → CsvRow, CsvSchema per метрика (per csv-contract.md
  mandatory columns: source, external_id, recorded_at, updated_at, synced_at,
  timezone, schema_version + метрик-специфичные колонки в frozen order)
- `client.rs` — HTTP client, error mapping (Network/RateLimited/Unauthorized/
  ServerError/ClientError/MalformedResponse — тот же набор вариантов, что
  WhoopApiError, НЕ логировать response body по D-015)
- `connect.rs` — OAuth authorization flow orchestration, использует
  `core::oauth::AuthorizationFlow::generate_state()` + `start()` +
  `validate_callback()` напрямую (T-403 — гап с генерацией state внутри
  start() исправлен, обходной паттерн WHOOP из T-401 больше не нужен)
- `sync.rs` — fetch/map/write orchestration, ADR-020 atomicity (все fetch
  успешны → пишем все CSV; любой fail → ничего не пишем)

### Что переиспользуется из core/ без изменений

- `core/oauth::AuthorizationFlow` — `generate_state()` → построить
  authorization_url со state → `start(connection_id, provider, state, url)`
  → дождаться callback → `validate_callback(connection_id, provider, result)`.
  CSRF/replay/expiry защита встроена, ничего не реализовывать вручную.
- `core/oauth::RefreshOrchestrator` + `BackoffSleeper` — провайдер передаёт
  свой `token_endpoint`/`client_id`/`client_secret` через `RefreshRequest`.
  Backoff-таблицы переиспользуются из `core/oauth::refresh`, не дублировать.
- `core/oauth::DisconnectOrchestrator` — провайдер передаёт свой
  `revoke_endpoint: Option<String>` (или `None`, если провайдер не
  поддерживает revoke, как временно WHOOP).
- `core/csv::{schema::CsvSchema, upsert::upsert, writer::CsvWriter}` —
  провайдер определяет только `metric_columns` через `CsvSchema::new(...)`.
- `core/sync::SyncState` — provider-агностичен по конструкции
  `(provider: String, connection_id, data_type)`; подключение к sync loop —
  вне scope коннектора, появится с EPIC-06.
- `core/connectors::rate_limiter::PacedThrottle` — переиспользовать напрямую
  с провайдер-специфичными `max_requests`/`window`.

### Провайдер-специфичные константы (в новом модуле, НЕ в core/)

- `base_url`, `token_endpoint`, `authorization_endpoint` (и `revoke_endpoint`,
  если есть)
- `scopes` — список обязательных/опциональных OAuth scopes
- rate limit (`max_requests`, `window`) для `PacedThrottle`
- endpoint paths для каждого типа данных
- client auth method (`client_secret_post` vs HTTP Basic — ПРОВЕРИТЬ на
  реальном API до финальной реализации; WHOOP ASSUMPTION по Basic Auth
  оказалась неверной, см. EPIC-04-providers.md T-401 "Ручная e2e-верификация"
  п.1 — не повторять эту ошибку без ручной проверки)

### Изоляция по провайдеру (D-008)

- `target_dir` для CSV конкретного provider/connection — ответственность
  вызывающей стороны (EPIC-06 sync engine, которого пока нет); модуль
  коннектора никогда не хардкодит общий/дефолтный путь — принимает
  `target_dir: PathBuf` параметром в своём `SyncRequest`.
- Имена CSV-файлов внутри `target_dir` НЕ включают provider-префикс
  (`sleep.csv`, не `whoop_sleep.csv`) — изоляция обеспечивается
  ИСКЛЮЧИТЕЛЬНО через разные `target_dir` per provider/connection.
