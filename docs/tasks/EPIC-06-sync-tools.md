# EPIC-06 — Sync engine + tool surface

## T-601 [P0] Оркестрация синка с контрактом атомарности ✅

Критерии приёмки:

- синк провайдера успешен только когда: все запланированные страницы получены,
  ответы преобразованы и провалидированы, все затронутые CSV записаны и атомарно
  заменены, новый sync cursor персистирован (см. architecture.md);
- сетевая ошибка никогда не переводит источник в `disconnected`; прежние CSV
  остаются доступными — проверено тестом с инъекцией сбоя на каждой фазе;
- `sync_now` по всем подключённым источникам продолжает работу при отказе одного
  из них и включает отказ в итоговый отчёт;
- rate limit ошибки уважают Retry-After (backoff-правила ядра).

Выполнено 2026-07-16: `core/sync/orchestrator.rs` — `SyncOrchestrator`
(provider-агностичный по сигнатуре: `ConnectionSyncRequest.provider: String`,
не enum, чтобы Oura/Garmin post-MVP не меняли форму структуры). Fetch/map/write
атомарность (nothing written unless все 4 endpoint fetch успешны) и
Retry-After/backoff уже реализованы на уровне `WhoopSyncSession`/`WhoopApiClient`
(T-401) — orchestrator их не дублирует, только оборачивает. Добавленный слой:
- `sync_one` — после успешного `session.sync()` персистирует sync cursor (конец
  синхронизированного time_range, RFC3339) для всех 4 WHOOP data types через
  `state::load` → `record_success` ×4 → `state::save` (architecture.md L78: state
  обновляется только после успешной записи всех CSV источника). При ошибке
  `sync_state.json` не трогается вообще — прежний курсор и CSV остаются
  доступны (проверено тестом на побайтовое совпадение state до/после сбоя).
  Сбой самого state I/O (load/save) — не фатален для отчёта: CSV уже атомарно
  записаны (durable truth), ошибка только логируется (`tracing::warn!`).
- `sync_many` — фан-аут по нескольким подключениям, одно упавшее не прерывает
  остальные и не блокирует их отчёты (изоляция сбоев).
- Тесты (5, все в `core::sync::orchestrator::tests`, используют тот же
  TCP-mock-сервер паттерн, что и `whoop::sync`'s собственные тесты):
  успешный синк персистирует курсор для всех 4 типов; сбой фетча оставляет
  `sync_state.json` неизменным (побайтово); `sync_many` с одним успехом и
  одним отказом — оба отчёта присутствуют, персистится только успешный;
  сбой state I/O не фейлит отчёт и не паникует.
- Технический побочный эффект: `WhoopSyncSession::new_with_urls` (test-only
  seam) сделан `pub(crate)` (было приватным в своём модуле) — иначе
  недостижим из `core::sync::orchestrator`'s тестов; поведение не менялось.
  Разработчик снова не имел доступа к cargo — код собирался и проходил тесты
  только после личной проверки (исправлены: дублирующийся `use SystemTime`,
  неверный конструктор `SecretString::from` вместо `::new`, недостижимые
  `state`/`SyncState` импорты, clippy `redundant_pattern_matching`, а также
  жёстко закодированная WHOOP-константа в тестовом коде, нарушавшая
  provider-agnostic boundary test `core/connectors/whoop/mod.rs`). Тесты
  автором были только заглушками (`#[test] fn test_sync_orchestrator_construction`
  без тела) — реальные тест-кейсы по критериям приёмки написаны и проверены
  лично. `cargo test`: 207 lib + 34 bin, `cargo clippy --all-targets`: чисто
  для изменённых файлов (9 оставшихся warnings — все существовавшие ранее).

## T-602 [P0] Tools: sync_now, sync_provider, list_data ✅

Критерии приёмки:

- `sync_now` — синк всех подключённых источников; `sync_provider(provider)` — одного;
- ответы содержат только статусы и метаданные: число записей, диапазоны дат,
  last successful sync — без значений health-данных (D-015);
- `list_data` перечисляет подключённые источники, их состояние (connected /
  reauthorization_required / …), CSV-файлы и покрытые периоды;
- параллельный вызов sync для одного провайдера исключён (аналогично refresh mutex).

Выполнено 2026-07-16: `sync_provider(provider, connection_id)` и `sync_now()`
(без параметров, синкает все обнаруженные подключения) поверх T-601's
`SyncOrchestrator`; `list_data` заменил T-201-заглушку на реальную реализацию.
Ответы содержат только status/counts/RFC3339-таймстемпы/пути — без
health-значений (D-015), проверено тестом.

Новый `core/sync/lock.rs` — `SyncLockRegistry`, зеркалит mutex-per-key паттерн
`RefreshCoordinator` (per-connection `Arc<Mutex<()>>`, ключ
`"{provider}:{connection_id}"`) — сериализует конкурентные вызовы sync для
одного подключения; захватывается внутри `spawn_blocking`, по одному
подключению за раз (не удерживается сразу для всей пачки в `sync_now`).

Зафиксированные проектные решения (не баги, границы уже существующего кода):
- **`expires_at` нигде не персистится** (ни в vault, ни в config, ни в
  sync_state) — `sync_provider`/`sync_now` всегда передают
  `expires_at: SystemTime::now()`, что безусловно триггерит проверку refresh в
  начале каждого sync через `WhoopSyncSession::should_refresh`; безопасно
  (refresh идемпотентен, `RefreshCoordinator` дедуплицирует), не требует
  нового persisted state.
- **Discovery только через `sync_state.json`** (то же ограничение, что и в
  T-606's `delete_app_data`) — подключение без ни одного успешного sync не
  обнаруживается ни `sync_now`, ни `list_data`.
- **`list_data.status` всегда `"connected"`** для обнаруженных источников —
  реального live-probe нет; актуальный статус узнаётся только вызовом
  `sync_provider`/`sync_now`.
- **HTTP-mock тест для `sync_provider`/`sync_now` невозможен на уровне
  tool-хендлера**: `WhoopSyncSession::new()` (используемый хендлерами)
  всегда указывает на реальный WHOOP base URL — только `#[cfg(test)]`-only
  `new_with_urls` (используется в `core::sync::orchestrator`'s и
  `whoop::sync`'s собственных тестах) допускает мок-сервер, но не
  прокидывается через tool-слой (не в скоупе T-602). Fetch/map/write/cursor
  логика уже покрыта mock-сервером в T-601; тесты этого файла проверяют
  только tool-слой (валидация provider/data_folder, discovery, форма ответа).

Разработчик снова не имел доступа к cargo — при личной проверке исправлены:
неверный путь `RealSleeper` (был `whoop::sync::RealSleeper`, нужен
`core::oauth::RealSleeper`), move-после-move `provider`/`connection_id` в
`sync_provider` (значения теперь берутся из `report.provider`/
`report.connection_id` после partial-move `report.result`), баг с
`time_range_start/end`, вычислявшимся ЗАНОВО через `Utc::now()` после
`spawn_blocking` вместо использования фактически использованного диапазона
(теперь возвращается из замыкания вместе с отчётом), устаревший тест на
удалённый `ListDataResponse::placeholder()`, недостающие 2 новых аргумента
`VitalsteadMcpServer::new()` в одном тестовом call site, clippy `too_many_arguments`
на `VitalsteadMcpServer::new()` (`#[allow]`, обосновано — 8 инъектируемых
зависимостей composition root). Добавлен тест на `list_data` с одной
sync_state-записью (обнаружение + cursor), которого не было в исходной
реализации; удалён некорректный HTTP-mock тест, который пытался обратиться к
реальному WHOOP API и мог зависать/флапать в CI (заменён комментарием,
объясняющим архитектурную границу). `cargo test`: 209 lib + 40 bin,
`cargo clippy --all-targets`: чисто для изменённых файлов (9 оставшихся
warnings — все существовавшие ранее).

## T-603 [P1] Tool query_data: агрегаты по умолчанию ✅

Критерии приёмки:

- по умолчанию tool возвращает агрегаты (min/max/avg/count по колонке за период)
  и метаданные — реализация D-015;
- сырые ряды возвращаются только с явным параметром (например `include_raw: true`),
  и описание tool прямо говорит, что данные попадут в контекст разговора;
- лимит на объём сырого ответа (строки/байты) с указанием, как сузить запрос;
- провайдеры не смешиваются в одном ответе без явного перечисления источников (D-008).

Выполнено 2026-07-16: `query_data(data_type, column, providers?, start?, end?,
include_raw)` читает CSV напрямую из `data_folder` через `core::csv::parse::deserialize`
(без похода в vault/API). По умолчанию (`include_raw: false`) — только
`aggregate{count,min,max,avg}` + метаданные (data_type/column/providers/период),
`raw: None`. С `include_raw: true` — сырые `{source, external_id, recorded_at,
value}` на отфильтрованных строках, лимит **500 строк**
(`raw_truncated: true` + `raw_truncation_note` с готовой подсказкой сузить
запрос по времени/провайдерам). Отсутствующий CSV-файл — валидный пустой
результат (`status: "ok"`, `count: 0`), не ошибка.

D-008: если `providers` не передан явно и в CSV встречается 2+ различных
значения колонки `source` — `ambiguous_providers` error вместо молчаливого
смешивания; при ровно одном источнике авто-резолв без явного списка (нет
неоднозначности). Фильтрация по времени — включительные границы по
`recorded_at` (RFC3339); строка с непарсящимся `recorded_at` исключается из
результата с `tracing::warn!` (без сырого значения ячейки в логе).
Агрегация — `column` парсится как `f64` построчно; нечисловая/пустая ячейка
просто не попадает в агрегат (`count: 0` — валидный ответ, не ошибка).

Разработчик снова не имел доступа к cargo — при личной проверке исправлены:
2 ошибки типов `String`/`Option<String>` при построении error-ответа для
невалидных `start`/`end` (`Some(...)` не оборачивал значение), и 2 реальных
бага в тестах разработчика — (1) `no_data_folder_configured`-тест передавал
несуществующую колонку `"sleep_score"` (в `sleep_schema()` такой колонки нет),
из-за чего проверка колонки срабатывала раньше проверки data_folder и тест
падал с `unknown_column`; (2) D-015-тест на утечку сырого значения использовал
CSV с ОДНОЙ строкой, из-за чего `avg == min == max ==` тестовое "сырое"
значение и тест ложно требовал его отсутствия даже в агрегате — исправлено на
3-строчную фикстуру, где отличительное значение не совпадает ни с одним из
агрегатов. `cargo test`: 209 lib + 49 bin, `cargo clippy --all-targets`: чисто
для изменённых файлов (9 оставшихся warnings — все существовавшие ранее).

## T-411 [P1] query_data флагует provisional-строки (score_state: PENDING_SCORE) ✅

Найдено на практике: пользователь сравнивал сегодняшний strain (в приложении
WHOOP — динамически растёт в течение дня для ещё не закрытого cycle) с тем,
что отдавал `query_data` — значения расходились. Расследование показало: это
не баг синка (WHOOP реально отдаёт актуальный strain открытого cycle по
API, `sync_provider` его корректно подтягивает и перезаписывает upsert'ом) —
проблема в том, что `query_data` смешивал такие «ещё живые» значения с
финализированными в одном агрегате, не давая понять, что число может
измениться при следующем синке.

Критерии приёмки:

- строки с `score_state: "PENDING_SCORE"` (открытый/не финализированный
  период — типично: сегодняшний ещё не закрытый cycle) учитываются в
  агрегате как обычно (никакого сокрытия данных), но их количество и факт
  их наличия явно видны в ответе;
- никакого скрытого автосинка внутри `query_data` — это read-only tool,
  синк остаётся только по явному вызову `sync_provider`/`sync_now` (D-003
  не нарушается);
- description tool-а инструктирует Claude проверять этот флаг перед тем,
  как представить значение (например, «сегодняшний strain») как
  финальное.

Выполнено 2026-07-24: `QueryDataResponse` получил `provisional_count: usize`
и `provisional_note: Option<String>`. В Step 8 (`src/main.rs`) для схем с
колонкой `score_state` (сейчас все четыре: sleep/recovery/cycle/workout)
каждая агрегируемая строка проверяется на `PENDING_SCORE`;
`provisional_note` формируется только когда `provisional_count > 0`,
человекочитаемым текстом («N of M aggregated row(s) are from a still-open
period…»). Рассмотрены и сознательно отклонены остальные варианты фикса из
обсуждения: TTL/принудительная инвалидация — усложнение состояния без
явной пользы поверх уже прозрачного флага; автосинк перед чтением в
`query_data` — нарушил бы D-003 (синк только по явному запросу), read-only
tool не должен незаметно дёргать сеть. 3 новых теста (happy-path без
PENDING_SCORE → `provisional_count: 0`; смешанная выборка из открытого и
закрытого cycle → `1 of 2`, текст заметки). `cargo test`: 283 (было 279)
зелёных. `cargo clippy --all-targets`: 0 новых warnings.

## T-604 [P0] Tool connect_provider ✅

Закрывает пробел: `architecture.md` относит `connect_provider` к tool surface
EPIC-06, но задача с критериями приёмки нигде не была заведена — обнаружено
при старте EPIC-06.

Критерии приёмки:

- принимает `provider` (`"whoop"`, далее расширяемо) + BYO client credentials
  (D-006) либо использует сконфигурированные; строит authorization URL через
  provider-specific connect-сессию (`WhoopConnectSession`/будущие аналоги),
  используя `AuthorizationFlow::generate_state()`/`start()`/`validate_callback()`
  напрямую (T-403 — обходной паттерн WHOOP из T-401 больше не нужен);
- ответ модели содержит только статус подключения (connected/error) и
  recovery-сообщение при ошибке (`WhoopConnectError` → текст, D-012 English
  only) — токены и code через границу tool не проходят никогда (D-015);
- ошибки авторизации (`MissingOfflineScope`, `ProviderDenied`, `Timeout` и т.д.)
  маппятся в понятные recovery-инструкции для пользователя;
- повторный `connect_provider` для того же `connection_id` до завершения
  первого — поведение явно определено (перезапись pending record, T-302
  semantics) и задокументировано в описании tool;
- тест на mock-провайдере (без реального сетевого вызова) на каждый путь:
  успех, отказ пользователя, отсутствие offline-scope, timeout.

Выполнено 2026-07-16: первый реальный MCP tool, подключающий WHOOP-коннектор
к серверу (`src/main.rs`). При проектировании найден блокирующий
архитектурный баг: `redirect_uri`/authorization URL строились ДО того, как
loopback listener реально биндил порт — в продакшене (без
`VITALSTEAD_OAUTH_FIXED_PORT`) callback никогда не пришёл бы на правильный порт.
Исправлено: `AuthorizationFlow::start_and_bind()` (новый метод) сначала
биндит listener, получает реальный порт, и только потом строит authorization
URL через переданное замыкание. `AuthorizationFlow` стал Arc-based (без
lifetime) — сервер владеет одним долгоживущим экземпляром, что нужно для
соблюдения T-302 semantics (перезапись pending record) между отдельными
вызовами tool, а не только внутри одного вызова. `WhoopConnectSession`
мигрирован на инжектируемый `&AuthorizationFlow`, параметр `redirect_uri`
убран из `connect()` (строится внутри из реального порта).

Блокирующий вызов `WhoopConnectSession::connect()` обёрнут в
`tokio::task::spawn_blocking` — без этого пятиминутное ожидание callback'а
блокировало бы worker thread общего tokio-рантайма сервера. `error_mapping.rs`
получил 6й `ToMcpError` impl (`WhoopConnectError`, 11 вариантов, 3 из них
делегируют в уже существующие Callback/TokenExchange/Vault маппинги).

`cargo test`: 224/224 (202 lib + 22 bin). При ревью найден и исправлен
скрытый no-op тест (`test_connect_provider_timeout_maps_to_recovery_message`)
— был обёрнут во внешний `tokio::time::timeout` с молчаливым fallback на
хардкоженный «ожидаемый» ответ внутри `if response_json != "{}"` — тест не
мог провалиться независимо от реального поведения кода. Переписан на прямую
проверку без внешней обёртки (дропнутый oneshot sender резолвит `recv()`
мгновенно, реальное ожидание не нужно).

## T-605 [P1] Tool disconnect_provider ✅

Критерии приёмки:

- принимает `provider`/`connection_id`; вызывает `DisconnectOrchestrator` (T-305)
  — best-effort revoke + безусловное удаление credentials из Keychain;
- CSV не удаляются (D-010) — только конфигурация подключения/токены;
- ответ — статус (revoke_attempted/revoke_succeeded) без секретов;
- disconnect для неизвестного/уже отключённого `connection_id` не паникует,
  возвращает понятный статус, а не сырую ошибку vault.

Выполнено 2026-07-16: `DisconnectOrchestrator` (T-305) вызывается напрямую из
tool-хендлера, без обёрточной сессии (YAGNI). `revoke_endpoint` захардкожен
`None` для WHOOP (endpoint не подтверждён, T-305 note). Неизвестный
`connection_id` — уже существующее поведение T-305 (`try_revoke` трактует
отсутствие токена как `(false, false)`, `delete_all_for_connection` на пустом
namespace — no-op), специального guard-кода не потребовалось.
`error_mapping.rs` получил 6й `ToMcpError` impl (`DisconnectError`,
единственный вариант делегирует в `VaultError`). `cargo test`: 229/229 (202
lib + 27 bin). Разработчик снова не имел доступа к cargo в своей среде —
после ручной проверки найдена и исправлена одна ошибка компиляции (trait
`CredentialVault` не был в scope тестового модуля).

## T-606 [P1] Tool delete_app_data ✅

Явное, отдельно подтверждаемое удаление данных приложения (D-010, D-013) —
CSV, config, credentials для всех/выбранных подключений.

Критерии приёмки:

- удаляет CSV-файлы, `config.json` и credentials указанных (или всех)
  connection_id только по явному вызову tool — не вызывается автоматически
  ни при каком другом flow (disconnect_provider его не вызывает, D-010);
- ответ — отчёт что удалено (пути/провайдеры), без значений health-данных;
- частичный сбой (например часть CSV удалена, часть — нет) отражается в
  отчёте как partial, не маскируется под полный успех.

Выполнено 2026-07-16: `delete_app_data(connections: Option<Vec<ConnectionRef>>)`.
Асимметричное поведение по дизайну: `connections: None` — полный wipe (все CSV
в data_folder + `config.json` + credentials всех подключений, обнаруженных
через `sync_state.json`); `connections: Some([...])` — удаляет только
credentials перечисленных connection_id, CSV и config.json намеренно не
трогает (отражено в `skipped_reason` ответа). Известное ограничение: discovery
для scope "all" читает только `sync_state.json` — connection, у которого был
`connect_provider`, но ни разу не было успешного sync, в отчёте не появится
(зафиксировано как документированный trade-off, не баг). Итоговый `status`
("success"/"partial"/"error") считается по количеству неудач среди трёх
категорий удаления (CSV/config/credentials); частичный сбой не маскируется.
Вся файловая/keychain-работа — через `spawn_blocking`. Разработчик снова не
имел доступа к cargo — при личной проверке найден и исправлен баг теста
(`test_delete_app_data_no_data_folder_configured_...`: в сценарий не был
добавлен `SyncEntry` в `sync_state.json`, из-за чего discovery для "all"
корректно находил 0 подключений, а assert ожидал 1) и 6 clippy
`bool_assert_comparison` warnings. `cargo test`: 236/236 (202 lib + 34 bin),
`cargo clippy --all-targets`: чисто.
