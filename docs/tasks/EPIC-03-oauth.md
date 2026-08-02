# EPIC-03 — OAuth end-to-end (loopback callback)

Замещает deep-link-ветку родительского EPIC-03: callback принимает временный
HTTP-listener на 127.0.0.1 (см. architecture.md → «OAuth»). Родительские
T-201 (Keychain) и ядро T-202 (state machine) уже перенесены и работают.

## T-301 [P0] Localhost loopback listener ✅

Закрывает GAP родительского T-202 (`listen_for_callback` — заглушка).

Критерии приёмки:

- временный HTTP-listener на 127.0.0.1 со свободным портом, redirect_uri вида
  `http://127.0.0.1:{port}/callback`;
- результат (code/error + state) доставляется через существующий `CallbackReceiver`;
- listener гасится после первого запроса или по таймауту 5 минут (контракт T-006);
- браузеру отдаётся страница «можно закрыть вкладку» без отражения параметров запроса;
- полный callback URL не логируется (Security rules);
- варианты `CallbackError` пересмотрены под loopback-семантику
  (`SchemeNotRegistered` → `ListenerBindFailed` или эквивалент) с обновлением тестов;
- редирект-запросы с чужим/отсутствующим `state` отклоняются и не гасят ожидание
  легитимного callback.

Выполнено 2026-07-15: `listen_for_callback` (`src/platform/macos/oauth_callback_handler.rs`)
биндит голый `std::net::TcpListener` на `127.0.0.1:0` (OS выбирает порт), конвертирует
в tokio и запускает фоновую `run_listener` — цикл `accept` с общим дедлайном
`AUTHORIZATION_TIMEOUT` (единый источник правды, без задублированных magic-чисел);
ручной парсинг HTTP request-line и percent-decode query string (без новых внешних
зависимостей — только `tokio` features `net`/`time`); ответ — три статические
HTML-константы без подстановки query-данных (XSS-safe по построению, не только по
тестам). Невалидный/отсутствующий `state` → HTTP 400, `continue` в цикле (ожидание
легитимного callback не гасится) — покрыто сквозным тестом с двумя последовательными
TCP-соединениями. `CallbackReceiver` получил поле `port`; тип канала расширен до
`Result<CallbackResult, CallbackError>`, чтобы таймаут доставлялся тем же каналом.
`CallbackError::SchemeNotRegistered` → `ListenerBindFailed`, каскадом обновлён
`error_mapping.rs` (T-203) и мок в `core/oauth/authorization.rs`. `cargo test`:
134/134. QA-ревью прошло с первого цикла (1 некритичное замечание — устаревшие
doc-комментарии про deep-link-семантику в `authorization.rs` — исправлено тем же
изменением). Известное ограничение: детерминированный тест на реальный
`ListenerBindFailed` (bind failure) не написан — OS почти всегда выдаёт свободный
порт на `127.0.0.1:0`; путь покрыт unit-тестом маппинга в `error_mapping.rs`.

## T-302 [P0] Хранилище pending authorization + защита от replay ✅

Порт родительского T-208 (найдено QA-ревью T-202) — критерии сохранены:

- добавлено in-memory хранилище pending authorization (persistent store не требуется:
  состояние подключения не переживает перезапуск сервера);
- `PendingAuthorization` удаляется сразу после первой попытки использования
  (успех или ошибка — попытка делает запись недействительной);
- тест воспроизводит повторное предъявление уже использованного callback и проверяет
  `Err(AuthorizationError::NoMatchingPendingAuthorization)` (или эквивалент),
  а не только случай `None`.

Выполнено 2026-07-15: `AuthorizationFlow` (`src/core/oauth/authorization.rs`) получил
поле `pending: Mutex<HashMap<String, PendingAuthorization>>`, ключ — `connection_id`
(не `state`, т.к. `CallbackResult::Error` его не содержит). `start()` вставляет
запись; `validate_callback()` сменил сигнатуру (принимает `connection_id` вместо
`pending: Option<&PendingAuthorization>` от вызывающей стороны) и атомарно вынимает
запись через `remove()` до всех проверок (state/provider/expiry) — удаление
происходит независимо от исхода валидации. Вариант ошибки
`AuthorizationError::NoMatchingPendingAuthorization` уже существовал в коде и
переиспользован без изменений. Тесты расширены с 8 до 10: T6 переписан на реальный
replay через стор (не голый `None`), добавлены T9 (replay после неуспешной
валидации) и T10 (неизвестный `connection_id`). Изменения ограничены одним файлом
(`error_mapping.rs` и `adapters/oauth_callback_handler.rs` вне scope, не тронуты).
`cargo test`: 136/136 (121 lib + 15 integration). QA-ревью прошло с первого цикла,
без замечаний.

## T-303 [P0] TokenExchangeClient на reqwest ✅

Закрывает GAP родительского T-203 (реальной реализации трейта нет).

Критерии приёмки:

- `exchange_code` и `refresh_token` выполняют реальные HTTP-запросы к token endpoint
  (form-encoded, client auth по правилам провайдера);
- таймаут 30s на запрос (providers.md родителя);
- HTTP-статусы и `error`-поля ответов маппятся в существующие варианты
  `TokenExchangeError` (Network / RateLimited / InvalidGrant / ClientError / Server);
- Authorization headers, тела запросов и ответов token endpoint не логируются;
- покрыто тестами против локального мок-сервера (без обращений к реальным провайдерам).

Выполнено 2026-07-15: `ReqwestTokenExchangeClient` (`src/adapters/reqwest_token_exchange_client.rs`)
— `reqwest::blocking::Client` (трейт синхронный, вызывается под `Mutex` в
`core/oauth/refresh.rs`), `default-features = false` + `rustls-tls` (без OpenSSL),
`timeout(30s)`. Form-encoded тело для `authorization_code`/`refresh_token` grant;
client auth — HTTP Basic (`client_id:client_secret`) при наличии секрета, иначе
`client_id` в теле (public client) — задокументировано как допущение, требующее
сверки при подключении конкретного провайдера в EPIC-04. Полный маппинг статусов
в 5 вариантов `TokenExchangeError`, включая fallback на malformed JSON и
неподдержанный HTTP-date формат `Retry-After` (только целые секунды). Секреты
(`access_token`/`refresh_token`) оборачиваются в `SecretString` сразу при
парсинге DTO; `OAuthErrorDto` структурно не содержит поля `error_description` —
утечка исключена на уровне типа, а не только по соглашению. Тесты — блокирующий
mock-HTTP-сервер (переиспользован паттерн ручного TCP-парсинга из T-301), без
новых dev-зависимостей; 18 тестов. `cargo test`: 154/154 (139 lib + 15
integration). QA-ревью: 1 цикл доработки (dead-code поле `request_line` в
тестовом хелпере → clippy warning, не security — использовано в assert на
`POST`, заодно закрыт пробел в покрытии метода запроса). Вне scope T-303:
подключение клиента в `lib.rs` composition root — это T-304.

## T-304 [P0] Wiring refresh-оркестратора ✅

Родительский T-203: оркестратор (`core/oauth/refresh.rs`) уже перенесён; задача —
подключить его к реальным `TokenExchangeClient` (T-303) и `CredentialVault`.

Критерии приёмки:

- refresh запускается до expiry и при 401 согласно правилам коннектора;
- ротация refresh token сохраняется атомарно; параллельный refresh исключён
  (per-connection mutex — уже в ядре, проверить интеграционно);
- `invalid_grant` переводит подключение в ReauthorizationRequired без удаления CSV.

Выполнено 2026-07-15: логика ротации/мьютекс-дедупа/`invalid_grant`-обработки уже
была полностью реализована и покрыта тестами на моках в T-203 — задача свелась к
wiring, не к новой разработке. Добавлен `build_token_exchange_client()` в
composition root (`src/lib.rs`) — кросс-платформенный (без `#[cfg(target_os)]`,
`ReqwestTokenExchangeClient` не платформозависим, architecture.md L91-97). 4
интеграционных теста прогоняют `RefreshOrchestrator`/`RefreshCoordinator`
(`src/core/oauth/refresh.rs`, не изменён) против РЕАЛЬНОГО HTTP-клиента и
локального mock-сервера (переиспользован паттерн T-303, без новых
dev-зависимостей): успешный refresh до expiry, атомарная ротация refresh_token
(assert на новое значение, не на «не упало»), дедуп параллельного refresh через
реальный сокет (два потока, один и тот же connection_id, mock принимает ровно
одно TCP-соединение), `invalid_grant` → `ReauthorizationRequired` с подтверждением
что vault НЕ изменился (store() не вызывался). `cargo test`: 143/143 lib. QA-ревью
прошло с первого цикла.

**Известное ограничение (вынесено в EPIC-04)**: критерий «refresh... при 401»
и переход `core::oauth::state::transition(..., ReauthorizationRequired)` НЕ
реализованы в T-304 — в репозитории пока нет connector/data-API клиента,
который бы детектировал HTTP 401 от провайдера и триггерил refresh(), и нет
caller'а, который вызывал бы `state::transition`. `RefreshOrchestrator` можно
вызвать по требованию в любой момент (не привязан к таймеру) — сам оркестратор
к этому готов; недостающая часть — sync loop/connector, который появится вместе
с EPIC-04 (провайдеры Oura/WHOOP). `src/core/oauth/state.rs` в T-304 не
изменялся.

## T-305 [P1] disconnect/revoke ✅

Порт родительского T-206 — критерии сохранены:

- вызывается официальный revoke-endpoint, если провайдер его предоставляет;
- локальные credentials удаляются из Keychain;
- CSV остаются до отдельного явно подтверждаемого удаления (D-010).

Выполнено 2026-07-15: `revoke_token` добавлен как новый метод существующего
трейта `TokenExchangeClient` (не отдельный трейт — тот же HTTP-клиент, та же
client-auth логика, что у `exchange_code`/`refresh_token`), реализован в
`ReqwestTokenExchangeClient` (POST form-encoded, RFC 7009). Новый
`DisconnectOrchestrator` (`src/core/oauth/disconnect.rs`): best-effort revoke
(если `revoke_endpoint: None` — сетевой вызов не происходит вообще, не просто
игнорируется) → безусловный `vault.delete_all_for_connection()` (единственный
`?` в методе — на самом delete, ошибка revoke никогда не блокирует локальное
отключение). Предпочтение `refresh_token` над `access_token` для отзыва
(аннулирует весь grant), имена credential kind сверены с реальным vault
(`platform/macos/credential_vault.rs`) — расхождения в именовании нет. CSV не
затронуты — ни один новый файл не импортирует `core::csv` (D-010). `cargo
test`: 159/159 lib. QA-ревью: 1 некритичное замечание (dead-code поле в
тестовом моке под строгим `clippy --all-targets`, не в рамках базового gate) —
исправлено (поле удалено, было ошибочно на не том моке). Вне scope, как и
T-303/T-304: MCP tool `disconnect_provider` — появится с connector framework
в EPIC-04.

## T-306 [P2] Усилить тест открытия системного браузера ✅

Порт родительского T-207 — критерии сохранены:

- мок `OAuthCallbackHandler` записывает URL, переданный в `open_system_browser`
  (например, через `Arc<Mutex<Vec<String>>>`);
- тест `test_start_opens_system_browser_with_generated_state`
  (`core/oauth/authorization.rs`) проверяет, что URL был передан и содержит
  сгенерированный `state`.

Выполнено 2026-07-15: `MockCallbackHandler` получил `captured_url:
Mutex<Option<String>>` (не `RefCell`, как в исходной формулировке критерия —
трейт `OAuthCallbackHandler` требует `Send + Sync`, `RefCell` не подходит; это
обнаруженный и корректно решённый гап, не отклонение от задачи).
`test_start_opens_system_browser_with_generated_state` проверяет
`captured == Some(auth_url)`. Критерий «URL содержит сгенерированный `state`»
выполнен **частично, с задокументированным архитектурным ограничением**:
`start()` (T-202) генерирует `state` внутри себя и возвращает его в
`PendingAuthorization`, но НЕ подставляет обратно в переданный
`authorization_url` — URL строится вызывающей стороной до вызова `start()`, и
сигнатура (`authorization_url: &str`, готовая строка) физически не позволяет
функции его переписать. Проверка «URL содержит state» на этом контракте
недостижима без изменения сигнатуры `start()` — это выходит за рамки P2-задачи
«усилить тест» и, если когда-либо понадобится для реального
провайдер-коннектора, требует отдельной задачи в EPIC-04 (где появится
реальный caller, строящий URL). `cargo test`: 159/159, без регрессий. QA-ревью
прошло с первого цикла.
