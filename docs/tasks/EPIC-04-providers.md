# EPIC-04 — Провайдеры: WHOOP (MVP), Oura (post-MVP)

Констрейнты провайдеров зафиксированы в родительском `providers.md` (T-002 LOCKED):
WHOOP — 100 req/min, access token 1 час, scope `offline` обязателен, overlap 24h;
Oura — 5000 req/5min, backfill 2 года, overlap 24h. Фикстуры — только анонимизированные
(Security rules).

Порядок провайдеров: WHOOP реализуется первым в MVP; Oura перенесён в post-MVP
трек (D-017) — продуктовое решение, не техническая зависимость.

## T-409 [P0] WorkoutRecord.sport_id: null ломал весь sync за глубокую историю ✅

Найдено на практике после T-407 (backfill): пользователь синкал реальный WHOOP-
аккаунт с разной глубиной (`days`) для локализации бага — 180 дней проходили,
210-400 падали с `sync.fetch_failed`. Гипотеза «за старый период просто нет
данных» не подтвердилась (WHOOP отвечал `200 OK`, не пустым результатом).
T-408 (см. ниже) сделал видимой diagnostic-запись `shape=`/`parse_error=`,
которая до этого молча терялась (`tracing::warn!` под фильтром по умолчанию
`ERROR`-only). В логе нашлось: `endpoint="/activity/workout"`,
`parse_error=invalid type: null, expected i64` — WHOOP отдаёт
`sport_id: null` для части тренировок (нераспознанный/кастомный тип
активности), а `WorkoutRecord.sport_id` в `dto.rs` был объявлен обязательным
`i64` — вся страница (25 записей) не парсилась при первом же таком workout,
что статистически чаще встречается на длинной истории, чем на последних 7-180
днях.

Фикс: `src/core/connectors/whoop/dto.rs` — `sport_id: i64` → `sport_id:
Option<i64>` (`#[serde(default)]`); `mapping.rs::map_workout` —
`record.sport_id.to_string()` → `record.sport_id.map(|v| v.to_string())`
(пустая CSV-ячейка вместо паники/некорректного числа). 3 новых теста:
deserialize с `sport_id: null` и с реальным значением (`dto.rs`), map_workout
с `None` не паникует и даёт пустую колонку (`mapping.rs`). `cargo test`: 279
(было 276) зелёных.

## T-408 [P1] Diagnostic-лог malformed-response поднят с WARN до ERROR ✅

Побочный, но необходимый для диагностики T-409 фикс: `redact_json_shape`-
диагностика в `client.rs` (структура полей 2xx-ответа, который не распарсился
— значения редактированы, D-015-safe) писалась через `tracing::warn!`, а
`tracing_subscriber::EnvFilter::from_default_env()` без `RUST_LOG` в env
по умолчанию показывает только `ERROR` — то есть эта диагностика была
невидима в любом реальном плагин/MCPB деплое (там `RUST_LOG` не выставлен).
Баг T-409 иначе было бы невозможно найти без ручного добавления `RUST_LOG`
и повторной сборки. `tracing::warn!` → `tracing::error!`, плюс в лог
добавлен `parse_error` (`serde_json`-ошибка — описывает несовпадение
типа/структуры, никогда не значение, безопасно по D-015).

## T-401 [P0] WHOOP connector ✅

Критерии приёмки:

- scope `offline` запрашивается всегда; его отсутствие в гранте — ошибка подключения
  с понятным recovery-сообщением;
- 4 CSV: sleep, recovery, cycles, workouts;
- бюджетирование запросов под лимит 100 req/min (расчёт числа страниц + троттлинг),
  429 обрабатывается по backoff-правилам ядра;
- refresh-путь проверен интеграционно: access token живёт 1 час, синк длиннее часа
  не падает;
- тесты на анонимизированных фикстурах.

Выполнено 2026-07-15: новый модуль `src/core/connectors/whoop/` — `WhoopApiClient`
(reqwest::blocking, статус-маппинг в `WhoopApiError`), `dto.rs`/`mapping.rs`
(DTO+CsvSchema для 4 CSV, поля WHOOP API v2 — **ASSUMPTION**, не подтверждено
реальным API, требует сверки на ручном e2e), `WhoopConnectSession` (авторизация +
scope-проверка), `WhoopSyncSession` (fetch-all-then-write-all, ADR-020).
`PacedThrottle` (`src/core/connectors/rate_limiter.rs`) переиспользует
`BackoffSleeper` из refresh.rs (ADR-019); 429/network/server backoff-числа —
те же таблицы, что в `core/oauth/refresh.rs` (2/4/8/16/32s capped 60 для
rate-limit, 1/2/4s network, 2/4/8s server).

Найден и временно обойдён архитектурный гап: `AuthorizationFlow::start()` (T-302)
генерировал CSRF state внутри себя и сам открывал браузер, но WHOOP authorization
URL требует state ДО открытия браузера — циклическая зависимость. На момент T-401
`WhoopConnectSession` не использовал `AuthorizationFlow`, а работал с
`OAuthCallbackHandler` напрямую (генерировал state сам, ручная валидация callback).
QA подтвердил тогда: это не регресс безопасности — single-shot `tokio::oneshot`
канал в loopback listener (T-301) давал эквивалентную защиту от replay, что и
atomic pending-record removal в T-302. **Гап устранён в T-403**:
`AuthorizationFlow::start()` теперь принимает `state` параметром (новый метод
`generate_state()` для генерации до построения URL), `WhoopConnectSession`
мигрирован на использование `AuthorizationFlow::start()`/`validate_callback()`
напрямую — ручной обход убран.

Задача прошла 2 полных цикла разработки + 1 промежуточный QA-гейт (после первой
половины: DTO/client/rate-limiter) + 1 финальный QA-гейт (FAIL, blocking) + рабочий
цикл вручную (тесты на самый важный критерий — refresh в середине долгого синка,
и на атомарность fetch-all-then-write-all — были поверхностными
заглушками/`assert!(true)` после автоматического цикла доработки; переписаны на
реальные интеграционные тесты с mock-HTTP-сервером, mock-часами и захватом
Authorization-заголовков, подтверждающие: (а) refresh срабатывает ровно один раз
при пересечении границы истечения токена, поздние запросы используют новый токен;
(б) при отказе одного из 4 endpoint'ов после исчерпания ретраев ни один CSV не
записывается, включая уже успешно зафетченные). `cargo test`: 189/189.
`cargo clippy`: 0 warnings в новых файлах.

Известные ограничения (зафиксированы, не блокируют):
- `MCP tools connect_provider/sync_now`, backfill/overlap-логика, cursor-персист
  в `SyncState` — вне scope, появятся с EPIC-06 (sync engine);
- WHOOP revoke endpoint не подтверждён — `DisconnectOrchestrator` (T-305) уже
  поддерживает `revoke_endpoint: None` без изменений.

### Ручная e2e-верификация (2026-07-15) — выполнена, ASSUMPTION-поля исправлены

Полный цикл (авторизация → CSV на диске) пройден с реальным WHOOP-аккаунтом
пользователя (dev-only `VITALSTEAD_OAUTH_FIXED_PORT=53682`, redirect
`http://127.0.0.1:53682/callback`). Итог: `Synced { sleep_count: 3, recovery_count: 3,
cycle_count: 4, workout_count: 2 }`, все 4 CSV записаны с корректными заголовками.
Найдены и исправлены реальные расхождения с ASSUMPTION из spec:

1. **Client auth — `client_secret_post`, не HTTP Basic Auth.** Реальный WHOOP token
   endpoint отвечал `401 invalid_client` на Basic Auth; исправлено в
   `reqwest_token_exchange_client.rs` (exchange_code/refresh_token/revoke_token) —
   `client_id`/`client_secret` теперь всегда в теле формы. Независимо подтверждено
   сверкой с рабочей продакшн-интеграцией WHOOP в смежном проекте (Azlo/Supabase
   Edge Functions) — та же схема `client_secret_post`, тот же token/auth/API base URL.
2. **`RecoveryRecord.cycle_id` и `CycleRecord.id` — числа в JSON, не строки.**
   Исправлено на `i64` в `dto.rs`, конвертация в `String` только на границе
   `mapping.rs` (external_id — всегда текстовая колонка).
3. **`CycleRecord.end` — `null` для текущего (ещё не завершённого) цикла.**
   Исправлено на `Option<String>`. Пустые `strain`/`kilojoule`/heart_rate у
   последней (сегодняшней) строки cycles.csv — не баг, а ожидаемое поведение
   WHOOP API: метрики цикла считаются только после его завершения (следующим
   sleep-событием). Подтверждено независимо: у Azlo есть отдельная историческая
   баг-фикс миграция про эту же особенность WHOOP.
4. **`RecoveryRecord.created_at`** — не было в исходном ASSUMPTION, добавлено;
   `recorded_at` теперь берёт `created_at` (ближе по смыслу к «когда это
   произошло»), с fallback на `updated_at` если поле отсутствует.
5. **`MacOSCredentialVault::store()` не был идемпотентным** (отдельная находка,
   не про WHOOP DTO) — `keyring`/macOS `SecItemAdd` падает с "already exists" при
   повторной записи того же `(service, key)`. Впервые проявилось на реальном
   Keychain (моки в T-201/T-304 это не покрывали). Исправлено на upsert
   (delete-then-add) в `platform/macos/credential_vault.rs` — критично для
   refresh-путей (T-304), которые полагаются на перезапись.

Sleep- и Workout-DTO (`SleepRecord`, `WorkoutRecord`) подтверждены корректными
без изменений — распарсились с первого раза на реальных данных (3 sleep, 2
workout). `WhoopApiClient` также получил диагностику
(`redact_json_shape` в `client.rs`) — при 2xx-ответе с не тем JSON логирует
структуру полей (имена+типы) через `tracing::warn!`, но никогда значения
(D-015) — оставлена постоянно как защита от будущего дрейфа WHOOP API, а не
только как временный диагностический костыль.

Артефакт: `examples/whoop_manual_connect.rs` — ручной e2e-harness (не часть
`cargo test`/CI), с опцией `WHOOP_SKIP_OAUTH=1` для повторных прогонов без
браузера (переиспользует токены из Keychain, синк сам инициирует refresh при
необходимости — заодно ещё раз эмпирически проверяет AC#4 на реальном API).

## T-407 [P0] Первый sync WHOOP тянет историю, а не только 7 дней ✅

Найдено на практике: пользователь подключил WHOOP, `sync_now`/`sync_provider`
дважды вернули один и тот же диапазон 17-24 июля — данные за прошлый год на
стороне WHOOP игнорировались. Причина не в WHOOP API (endpoint принимает
произвольные `start`/`end`; `nextToken` — постраничная выдача внутри уже
заданного окна, не расширение истории) и не в курсоре (`time_range_start`
вообще не читался из курсора) — окно синка было жёстко закодировано в двух
местах `src/main.rs` как `now - 7 дней`, без разницы между первым и
повторным синком. Решения не было — implicit-хардкод, не D-0xx.

Критерии приёмки:

- первый синк подключения (нет ни одной записи в `sync_state.json` для этого
  `provider`+`connection_id`) тянет `DEFAULT_BACKFILL_SYNC_DAYS` (365 дней)
  вместо 7;
- повторный синк того же подключения остаётся инкрементальным
  (`DEFAULT_INCREMENTAL_SYNC_DAYS` = 7 дней), поведение не регрессирует;
- `sync_now`/`sync_provider` принимают опциональный параметр `days`,
  явно переопределяющий диапазон (1..=`MAX_SYNC_DAYS`=3650) — не только
  implicit backfill, но и ручной запрос произвольной глубины;
- невалидный `days` (<=0 или >3650) — структурированная ошибка
  `invalid_days` до похода в сеть, не паника и не тихое искажение диапазона;
- тесты на `resolve_sync_window`/`has_prior_sync` (обе ветки: первый/повторный
  синк, override, границы 1 и 3650) и на tool-слой (`invalid_days` для обоих
  tools).

Выполнено 2026-07-24: `src/main.rs` — `resolve_sync_window()` +
`has_prior_sync()` (проверяет `sync_state.json` на запись для
provider+connection_id перед вычислением окна), заменили оба хардкода
`now - Duration::days(7)` (`sync_provider`, `sync_now`). `SyncProviderParams`/
`SyncNowParams` получили поле `days: Option<i64>`. Валидация диапазона —
синхронно, до `spawn_blocking`, чтобы невалидный ввод не тратил цикл
sync/сеть. Для `sync_now`: т.к. discovery источников идёт исключительно
через `sync_state.json` (T-602's known limitation), обнаруженное подключение
по построению уже имеет запись — backfill-ветка там сработает только если
механизм discovery когда-нибудь изменится; тем не менее логика вычисляется
per-connection (не хардкодом true), чтобы не разойтись с `sync_provider` и
не превратиться в скрытое допущение. 8 новых unit-тестов, `cargo test`:
276 (было 267) зелёных, `cargo clippy --all-targets`: 0 новых warnings
в `src/main.rs`.

## T-403 [P1] Connector contract доказан на WHOOP + чеклист расширяемости ✅

**Выполнено 2026-07-15:** исправлен архитектурный гап `AuthorizationFlow::start()` 
(добавлена `generate_state()`, state теперь параметр start(), не генерируется внутри).
WHOOP мигрирован на использование AuthorizationFlow напрямую (убран ручной обход).
Добавлен чеклист в architecture.md, 2 новых теста (D-008 изоляция, утечка констант).
189 тестов проходят, 0 warnings.

Критерии приёмки (скорректированы D-017 — Oura ещё не реализован в рамках MVP):

- общий трейт коннектора покрывает WHOOP без провайдер-специфичных веток в sync
  engine и tool surface (архитектура готова принять второго провайдера без
  рефакторинга ядра);
- добавление нового OAuth-провайдера (включая Oura, когда он вернётся в работу)
  описано как checklist (какие файлы создать, что реализовать) в architecture.md;
- провайдеры не смешиваются в CSV/папках (D-008) — проверено тестом (даже с одним
  реальным провайдером тест должен подтверждать изоляцию по namespace/папке, готовую
  принять второй);
- буквальное «доказано на двух провайдерах» переносится на post-MVP: когда T-402
  (Oura) будет реализован, эта задача переоткрывается для финальной проверки, что
  трейт действительно не потребовал провайдер-специфичных веток.

## T-402 [POST-MVP] Oura connector

Перенесён из MVP-скоупа в post-MVP (D-017). Критерии приёмки сохранены без
изменений — актуальны при возврате к задаче:

- авторизация со scopes `daily`, `heartrate`, `workout`, `spo2` (+ опциональные
  `email`, `personal`, `tag` — по конфигурации);
- 6 CSV: sleep, activity, readiness, heart_rate, workouts, spo2 — схемы по
  унаследованному CSV-контракту (`core/csv/schema.rs`);
- пагинация и backfill до 2 лет при первом синке; overlap-window 24h при инкрементальном;
- upsert по `(source, external_id)` (D-009), sync cursor персистится только после
  успешного синка (контракт атомарности);
- полный цикл покрыт тестами на анонимизированных фикстурах ответов API.
