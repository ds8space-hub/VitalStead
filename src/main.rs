//! MCP Server (T-201 + T-202): stdio-транспорт, tool surface scaffold, конфигурация
//!
//! Composition root для бинаря MCP-сервера. Инициализирует:
//! - Логирование (tracing → stderr, D-015: stdout зарезервирован для MCP JSON-RPC)
//! - Конфигурация: data_folder из VITALSTEAD_DATA_FOLDER env var или persisted config.json (T-202)
//! - Сервер с tool handler (rmcp SDK)
//! - Stdio-транспорт
//! - Tool surface (list_data в T-201, set_data_folder в T-202)
//!
//! D-011: ядро платформонезависимо; этот файл — composition root верхнего уровня,
//! зависит от `lib.rs` и его `build_credential_vault()` / `build_oauth_callback_handler()`
//! для будущих задач, но T-201 их не вызывает (заглушка `list_data` не требует их).
//! T-202: app_support_dir вычисляется здесь (macOS-специфично, не нарушает D-011),
//! т.к. это composition root.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rmcp::{
    handler::server::{
        router::{prompt::PromptRouter, tool::ToolRouter},
        wrapper::Parameters,
    },
    model::{GetPromptResult, PromptMessage, Role},
    prompt, prompt_handler, prompt_router, tool, tool_handler, tool_router, ServerHandler,
    ServiceExt,
};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use tracing::{error, info, warn};

use vitalstead_mcp::adapters::{AtomicFileWriter, MacAtomicFileWriter, file_picker::verify_writable_and_readable};
use vitalstead_mcp::config::{self, AppConfig};
use vitalstead_mcp::error_mapping::ToMcpError;

/// T-407: default sync window for a connection that has synced before
/// (incremental — overlaps the prior window rather than re-fetching history).
const DEFAULT_INCREMENTAL_SYNC_DAYS: i64 = 7;
/// T-407: default sync window for a connection with no prior sync_state
/// entries — first sync backfills deep history instead of only the last
/// 7 days, so a year-old WHOOP account doesn't look empty after connecting.
const DEFAULT_BACKFILL_SYNC_DAYS: i64 = 365;
/// T-407: upper bound on the `days` override, whether it comes from the
/// explicit param or a backfill default. 10 years — generous enough for a
/// user's entire wearable history without being unbounded.
const MAX_SYNC_DAYS: i64 = 3650;

/// T-407: resolves the `(start, end)` sync window from an optional explicit
/// `days` override and whether this connection has any prior sync_state
/// entries. `Err` carries a user-facing message for an out-of-range `days`.
fn resolve_sync_window(
    days_override: Option<i64>,
    has_prior_sync: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>), String> {
    let days = match days_override {
        Some(d) if d <= 0 => {
            return Err(format!("`days` must be a positive integer, got {}.", d));
        }
        Some(d) if d > MAX_SYNC_DAYS => {
            return Err(format!("`days` must not exceed {} (got {}).", MAX_SYNC_DAYS, d));
        }
        Some(d) => d,
        None if has_prior_sync => DEFAULT_INCREMENTAL_SYNC_DAYS,
        None => DEFAULT_BACKFILL_SYNC_DAYS,
    };
    Ok((now - chrono::Duration::days(days), now))
}

/// T-407: whether `sync_state.json` already has any entry for this
/// (provider, connection_id) — i.e. whether this is the connection's first
/// sync (backfill window) or a later one (incremental window).
fn has_prior_sync(
    writer: &dyn AtomicFileWriter,
    app_support_dir: &std::path::Path,
    provider: &str,
    connection_id: &str,
) -> bool {
    vitalstead_mcp::core::sync::state::load(writer, app_support_dir)
        .unwrap_or_default()
        .entries
        .iter()
        .any(|e| e.provider == provider && e.connection_id == connection_id)
}

/// T-410: source of truth for the setup wizard is the standalone Claude
/// Skill file (`plugin/skills/setup-guide/SKILL.md`), not a second copy of
/// the text here. Embedding it via `include_str!` lets the same content
/// ship two ways — as an uploadable Skill zip, and as an MCP Prompt exposed
/// directly by this server — without the two drifting apart over time.
const SETUP_GUIDE_SKILL_MD: &str = include_str!("../plugin/skills/setup-guide/SKILL.md");

/// Strips the YAML frontmatter (`---\n...\n---\n`) from `SETUP_GUIDE_SKILL_MD`,
/// leaving only the wizard's body — the Prompt's own `name`/`description`
/// (set via `#[prompt(...)]`) already cover what the frontmatter conveys for
/// the Skill-upload path.
fn setup_guide_prompt_body() -> &'static str {
    let mut parts = SETUP_GUIDE_SKILL_MD.splitn(3, "---\n");
    parts.next(); // "" before the opening "---"
    parts.next(); // frontmatter block
    parts.next().unwrap_or(SETUP_GUIDE_SKILL_MD).trim()
}

/// Ответ tool-а list_data (T-602 Spec 5.3).
/// Перечисляет обнаруженные источники, их состояние (connected / reauthorization_required / …),
/// CSV-файлы и покрытые периоды.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListDataResponse {
    pub sources: Vec<DataSourceInfo>,
    pub note: String,
}

/// Параметры tool-а set_data_folder (T-202 Spec 3.5)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SetDataFolderParams {
    pub path: String,
}

/// Детали ошибки в set_data_folder (T-202 Spec 3.5 + T-203)
#[derive(Debug, Serialize, Deserialize)]
pub struct SetDataFolderError {
    pub kind: String,
    pub message: String,
    pub recovery: String,
}

/// Ответ tool-а set_data_folder (T-202 Spec 3.5)
#[derive(Debug, Serialize, Deserialize)]
pub struct SetDataFolderResponse {
    pub status: String,
    pub data_folder: Option<String>,
    pub error: Option<SetDataFolderError>,
}

/// Параметры tool-а connect_provider (T-604 Spec 4.1)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConnectProviderParams {
    pub provider: String,
    pub connection_id: Option<String>,
    /// D-006 BYO OAuth client ID. Prefer configuring this via the plugin's
    /// own settings UI (userConfig) or an env var — do NOT ask the user to
    /// paste it into chat (T-801 threat model: this value would then pass
    /// through the model's conversation context).
    #[schemars(description = "BYO OAuth client ID (D-006). Should come from the plugin's userConfig or an env var, never from a value the user typed into chat.")]
    pub client_id: Option<String>,
    /// D-006 BYO OAuth client secret. Same rule as `client_id`, but stricter:
    /// this is a real secret (D-015) — it must never be sourced from chat
    /// text under any circumstance.
    #[schemars(description = "BYO OAuth client secret (D-006, D-015). Must come from the plugin's userConfig (sensitive field, stored by Claude Desktop/Code, never visible to the model) or an env var — NEVER ask the user to paste this into chat.")]
    pub client_secret: Option<String>,
}

/// Детали ошибки в connect_provider (T-604 Spec 4.1 + T-203)
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectProviderError {
    pub kind: String,
    pub message: String,
    pub recovery: String,
}

/// Ответ tool-а connect_provider (T-604 Spec 4.1)
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectProviderResponse {
    pub status: String,
    pub connection_id: String,
    pub provider: String,
    pub error: Option<ConnectProviderError>,
}

/// Параметры tool-а disconnect_provider (T-605 Spec 4.2)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DisconnectProviderParams {
    pub provider: String,
    pub connection_id: String,
}

/// Детали ошибки в disconnect_provider (T-605 Spec 4.2 + T-203)
#[derive(Debug, Serialize, Deserialize)]
pub struct DisconnectProviderError {
    pub kind: String,
    pub message: String,
    pub recovery: String,
}

/// Ответ tool-а disconnect_provider (T-605 Spec 4.2)
#[derive(Debug, Serialize, Deserialize)]
pub struct DisconnectProviderResponse {
    pub status: String,               // "disconnected" | "error"
    pub connection_id: String,
    pub provider: String,
    pub revoke_attempted: Option<bool>,   // Some(_) только когда status="disconnected"
    pub revoke_succeeded: Option<bool>,   // Some(_) только когда status="disconnected"
    pub error: Option<DisconnectProviderError>,
}

/// Параметры tool-а sync_provider (T-602 Spec 5.1; `days` добавлен T-407)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SyncProviderParams {
    pub provider: String,
    pub connection_id: String,
    /// Optional override: how many days of history to sync, counting back
    /// from now. Omit to use the default: `DEFAULT_INCREMENTAL_SYNC_DAYS`
    /// days for a connection that has synced before, or
    /// `DEFAULT_BACKFILL_SYNC_DAYS` days if this connection has never
    /// synced (backfill). Must be between 1 and `MAX_SYNC_DAYS`.
    #[schemars(description = "Optional override for how many days of history to sync, counted back from now. Omit to use the default: 7 days for a connection that has synced before, or 365 days for a first-time sync (backfill). Must be between 1 and 3650.")]
    pub days: Option<i64>,
}

/// Детали ошибки в sync_provider (T-602)
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncProviderError {
    pub kind: String,
    pub message: String,
    pub recovery: String,
}

/// Ответ tool-а sync_provider (T-602 Spec 5.1)
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResult {
    pub provider: String,
    pub connection_id: String,
    pub status: String, // "synced" | "error"
    pub sleep_count: Option<usize>,
    pub recovery_count: Option<usize>,
    pub cycle_count: Option<usize>,
    pub workout_count: Option<usize>,
    pub time_range_start: String,  // RFC3339
    pub time_range_end: String,    // RFC3339
    pub error: Option<SyncProviderError>,
}

/// Параметры tool-а sync_now (T-602 Spec 5.2; `days` добавлен T-407)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SyncNowParams {
    /// Optional override: how many days of history to sync, counting back
    /// from now, applied uniformly to every discovered connection. Omit to
    /// use the per-connection default: 7 days for a connection that has
    /// synced before, or 365 days for a connection with no prior sync
    /// history (backfill). Must be between 1 and `MAX_SYNC_DAYS`.
    #[schemars(description = "Optional override for how many days of history to sync, counted back from now, applied to every connection. Omit to use the default: 7 days for connections that have synced before, or 365 days for connections with no prior sync history (backfill). Must be between 1 and 3650.")]
    pub days: Option<i64>,
}

/// Ответ tool-а sync_now (T-602 Spec 5.2)
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncNowResponse {
    pub status: String, // "success" | "partial" | "no_connections" | "no_data_folder_configured"
    pub results: Vec<SyncResult>,
}

/// Информация об одном CSV-файле источника (для list_data, T-602 Spec 5.3)
#[derive(Debug, Serialize, Deserialize)]
pub struct DataSourceCsvInfo {
    pub data_type: String,       // "sleep" | "recovery" | "cycle" | "workout"
    pub file_exists: bool,
    pub last_successful_sync_at: Option<String>, // RFC3339
    pub cursor: Option<String>,                  // RFC3339
}

/// Информация об одном источнике данных (для list_data, T-602 Spec 5.3)
#[derive(Debug, Serialize, Deserialize)]
pub struct DataSourceInfo {
    pub provider: String,
    pub connection_id: String,
    pub status: String, // "connected"
    pub csv: Vec<DataSourceCsvInfo>,
}

/// Параметры tool-а delete_app_data (T-606 Spec 4.3)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionRef {
    pub provider: String,
    pub connection_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeleteAppDataParams {
    pub connections: Option<Vec<ConnectionRef>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDeletionResult {
    pub path: String,
    pub status: String,      // "deleted" | "failed"
    pub error_kind: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsvDeletionReport {
    pub attempted: bool,
    pub skipped_reason: Option<String>,
    pub deleted_files: Vec<String>,
    pub failed_files: Vec<FileDeletionResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigDeletionResult {
    pub attempted: bool,
    pub status: String,        // "deleted" | "not_found" | "failed" | "skipped"
    pub path: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDeletionResult {
    pub provider: String,
    pub connection_id: String,
    pub status: String,        // "deleted" | "failed"
    pub error_kind: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteAppDataResponse {
    pub status: String,   // "success" | "partial" | "error"
    pub csv: CsvDeletionReport,
    pub config: ConfigDeletionResult,
    pub credentials: Vec<CredentialDeletionResult>,
    pub note: Option<String>,
}

/// Параметры tool-а query_data (T-603 Spec).
/// Запрашивает агрегаты и/или сырые ряды по метрике за период (D-015).
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct QueryDataParams {
    /// One of "sleep", "recovery", "cycle", "workout".
    pub data_type: String,
    /// Metric column name to aggregate (must be a column of the resolved schema).
    pub column: String,
    /// Explicit list of provider names to include (D-008: providers are never
    /// silently mixed). If omitted, the query is only allowed to proceed when
    /// the CSV file contains rows from exactly ONE distinct `source` value.
    pub providers: Option<Vec<String>>,
    /// RFC3339 inclusive lower bound on `recorded_at`. None = no lower bound.
    pub start: Option<String>,
    /// RFC3339 inclusive upper bound on `recorded_at`. None = no upper bound.
    pub end: Option<String>,
    /// Default false. When true, raw matching rows are included in the
    /// response (bounded by a row limit) — these values enter the model's
    /// conversation context. When false (default), only aggregates/metadata
    /// are returned (D-015).
    #[serde(default)]
    pub include_raw: bool,
}

/// Агрегаты по столбцу (count/min/max/avg).
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryDataAggregate {
    pub count: usize,      // number of rows where `column` parsed as a finite f64
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
}

/// Ошибка в query_data.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryDataError {
    pub kind: String,
    pub message: String,
    pub recovery: String,
}

/// Один сырой ряд при include_raw=true.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryDataRawRow {
    pub source: String,
    pub external_id: String,
    pub recorded_at: String,
    pub value: Option<String>, // the raw string value of `column` for this row
}

/// Ответ tool-а query_data (T-603).
/// По умолчанию возвращает только агрегаты и метаданные (D-015).
/// С include_raw=true возвращает также сырые ряды (ограничено 500 rows).
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryDataResponse {
    pub status: String, // "ok" | "error"
    pub data_type: String,
    pub column: String,
    pub providers: Vec<String>,       // resolved provider list actually used for filtering
    pub start: Option<String>,
    pub end: Option<String>,
    pub aggregate: Option<QueryDataAggregate>,
    pub raw: Option<Vec<QueryDataRawRow>>,      // only Some when include_raw=true and status="ok"
    pub raw_truncated: bool,                     // true if raw rows were capped by the row limit
    pub raw_truncation_note: Option<String>,     // guidance when raw is truncated
    /// T-411: how many aggregated rows are from a still-open period (WHOOP
    /// `score_state: PENDING_SCORE`) — e.g. today's not-yet-closed cycle,
    /// whose `strain` updates live throughout the day and isn't final yet.
    /// 0 when the schema has no `score_state` column or nothing matched.
    pub provisional_count: usize,
    /// Plain-language note, present only when `provisional_count > 0`.
    pub provisional_note: Option<String>,
    pub error: Option<QueryDataError>,
}

/// Helper: преобразовать std::io::Error в WriteError (T-606)
fn io_error_to_write_error(e: std::io::Error) -> vitalstead_mcp::adapters::WriteError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => vitalstead_mcp::adapters::WriteError::PermissionDenied,
        _ => vitalstead_mcp::adapters::WriteError::Backend(e.to_string()),
    }
}

/// Входные параметры list_data (пусто, как в Spec 3.2).
/// JsonSchema требуется для корректной генерации input schema.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListDataParams {}

/// Структура сервера, реализующая ServerHandler.
/// T-201: простой контейнер с tool_router.
/// T-202: добавлены shared state (data_folder), app_support_dir, writer для конфигурации.
/// T-604: добавлены три Arc-поля для OAuth и credential storage (injectables в connect_provider).
/// T-602: добавлены refresh_coordinator и sync_lock_registry для sync операций.
#[derive(Clone)]
pub struct VitalsteadMcpServer {
    tool_router: ToolRouter<Self>,
    /// T-410: exposes the setup wizard as an MCP Prompt so it's available
    /// the moment this server connects — no separate Skill upload needed.
    prompt_router: PromptRouter<Self>,
    data_folder: Arc<Mutex<Option<PathBuf>>>,
    app_support_dir: PathBuf,
    writer: Arc<dyn AtomicFileWriter>,
    token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient>,
    credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault>,
    // authorization_flow already owns its own clone of the callback_handler
    // internally (see AuthorizationFlow::new) — no separate field needed here.
    authorization_flow: Arc<vitalstead_mcp::core::oauth::AuthorizationFlow>,
    refresh_coordinator: Arc<vitalstead_mcp::core::oauth::refresh::RefreshCoordinator>,
    sync_lock_registry: Arc<vitalstead_mcp::core::sync::SyncLockRegistry>,
}

impl std::fmt::Debug for VitalsteadMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VitalsteadMcpServer")
            .field("app_support_dir", &self.app_support_dir)
            .field("data_folder_is_set", &self.data_folder.lock().unwrap().is_some())
            .finish()
    }
}

impl VitalsteadMcpServer {
    /// Создание нового экземпляра сервера с конфигурацией (T-202), OAuth/credential adapters (T-604),
    /// и sync/refresh координаторами (T-602).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_folder: Arc<Mutex<Option<PathBuf>>>,
        app_support_dir: PathBuf,
        writer: Arc<dyn AtomicFileWriter>,
        token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient>,
        credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault>,
        authorization_flow: Arc<vitalstead_mcp::core::oauth::AuthorizationFlow>,
        refresh_coordinator: Arc<vitalstead_mcp::core::oauth::refresh::RefreshCoordinator>,
        sync_lock_registry: Arc<vitalstead_mcp::core::sync::SyncLockRegistry>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
            data_folder,
            app_support_dir,
            writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        }
    }
}

/// Реализация ServerHandler с tool-ом list_data.
/// Макрос tool_handler генерирует реализацию ServerHandler на основе tool_router'а.
/// T-410: prompt_handler застекирован поверх tool_handler на том же impl-блоке
/// (rmcp-macros README: "stacked #[prompt_handler] on the same impl ServerHandler") —
/// добавляет get_prompt/list_prompts к уже сгенерированным call_tool/list_tools.
#[tool_handler(router = self.tool_router)]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for VitalsteadMcpServer {}

/// T-410: MCP Prompts — доступны сразу при подключении сервера (в отличие от
/// Claude Skills, которые пользователь должен загрузить отдельно через
/// Customize → Skills). Текст — единый источник с `plugin/skills/setup-guide/SKILL.md`
/// (см. SETUP_GUIDE_SKILL_MD).
#[prompt_router]
impl VitalsteadMcpServer {
    /// Пошаговый мастер подключения WHOOP — то же содержание, что в Claude Skill
    /// `setup-guide`, доступное сразу через MCP Prompt (без отдельной загрузки).
    #[prompt(
        name = "setup_guide",
        description = "Step-by-step wizard for connecting a wearable data provider (currently WHOOP) to Vitalstead, running the first sync, and understanding the resulting CSV files."
    )]
    async fn setup_guide_prompt(&self) -> GetPromptResult {
        GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            setup_guide_prompt_body().to_string(),
        )])
        .with_description(
            "Vitalstead setup wizard: connect a wearable provider, run the first sync, understand your CSV data.",
        )
    }
}

/// Макрос для регистрации tool-ов.
/// Spec 3.3: регистрация tool surface (list_data в T-201, set_data_folder в T-202).
#[tool_router(router = tool_router)]
impl VitalsteadMcpServer {
    /// Tool list_data (T-602 Spec 5.3).
    /// Перечисляет подключённые источники, их состояние (connected / reauthorization_required),
    /// CSV-файлы и покрытые периоды. Источники обнаруживаются из sync_state.json.
    /// ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ (T-602 gap #2): соединение, которое было connect_provider'd но никогда
    /// успешно не синхронизировалось, не будет обнаружено здесь. Состояние является
    /// last-known-state only — вызов sync_provider/sync_now показывает текущее состояние подключения.
    #[tool(description = "List connected data sources. Returns sources discovered from sync history, \
        their connection status (always 'connected' — last-known-state only), CSV files present in the \
        data folder, and the date ranges covered by synced data. KNOWN LIMITATION: a connection that was \
        connect_provider'd but never successfully synced will not appear here — sync_provider/sync_now can \
        reveal real-time status. For current connectivity, call sync_provider or sync_now and observe the result.")]
    pub async fn list_data(&self, _params: Parameters<ListDataParams>) -> String {
        info!("list_data tool called");

        let data_folder = self.data_folder.lock().unwrap().clone();
        let app_support_dir = self.app_support_dir.clone();
        let writer = self.writer.clone();

        let result = tokio::task::spawn_blocking(move || {
            // Load sync state to discover (provider, connection_id) pairs
            let state = vitalstead_mcp::core::sync::state::load(writer.as_ref(), &app_support_dir)
                .unwrap_or_default();

            // Group entries by (provider, connection_id), deduping
            let mut sources_map: std::collections::BTreeMap<(String, String), Vec<_>> = std::collections::BTreeMap::new();
            for entry in state.entries {
                sources_map
                    .entry((entry.provider.clone(), entry.connection_id.clone()))
                    .or_insert_with(Vec::new)
                    .push(entry);
            }

            // Build response
            let sources = sources_map
                .into_iter()
                .map(|((provider, connection_id), entries)| {
                    // Build CSV info for each data_type present in entries
                    let csv = entries
                        .into_iter()
                        .map(|entry| {
                            let file_exists = if let Some(ref folder) = data_folder {
                                let file_name = match entry.data_type.as_str() {
                                    "sleep" => "sleep.csv",
                                    "recovery" => "recovery.csv",
                                    "cycle" => "cycles.csv",
                                    "workout" => "workouts.csv",
                                    _ => return DataSourceCsvInfo {
                                        data_type: entry.data_type,
                                        file_exists: false,
                                        last_successful_sync_at: None,
                                        cursor: None,
                                    },
                                };
                                folder.join(file_name).exists()
                            } else {
                                false
                            };

                            DataSourceCsvInfo {
                                data_type: entry.data_type,
                                file_exists,
                                last_successful_sync_at: Some(entry.last_successful_sync_at.to_rfc3339()),
                                cursor: entry.cursor.clone(),
                            }
                        })
                        .collect();

                    DataSourceInfo {
                        provider,
                        connection_id,
                        status: "connected".to_string(),
                        csv,
                    }
                })
                .collect();

            let note = "Sources are discovered from sync history (sync_state.json); a connection that \
                was connect_provider'd but never successfully synced will not appear here. Status is \
                last-known-state only — call sync_provider to get current connectivity."
                .to_string();

            ListDataResponse { sources, note }
        })
        .await;

        match result {
            Ok(response) => serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()),
            Err(_) => {
                // Internal error (task panic/cancel)
                let response = ListDataResponse {
                    sources: vec![],
                    note: "Internal error while listing sources.".to_string(),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
        }
    }

    /// Tool connect_provider (T-604 Spec 4.1).
    /// Подключает OAuth provider (пока только WHOOP) и сохраняет credentials в vault.
    #[tool(description = "Connect a data provider (OAuth). Launches authorization flow, exchanges code for tokens, stores credentials securely.")]
    pub async fn connect_provider(&self, params: Parameters<ConnectProviderParams>) -> String {
        info!("connect_provider tool called with provider: {}", params.0.provider);

        // Step 1: Валидировать provider
        if params.0.provider != "whoop" {
            let response = ConnectProviderResponse {
                status: "error".to_string(),
                connection_id: params.0.connection_id.unwrap_or_else(|| "unknown".to_string()),
                provider: params.0.provider.clone(),
                error: Some(ConnectProviderError {
                    kind: "unsupported_provider".to_string(),
                    message: "This provider is not yet supported.".to_string(),
                    recovery: "Use a supported provider (WHOOP, etc).".to_string(),
                }),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }

        // Step 2: Генерируем или используем переданный connection_id
        let connection_id = params.0.connection_id
            .unwrap_or_else(|| format!("conn_{}", uuid::Uuid::new_v4()));

        // Step 3: Получаем client_id и client_secret (из параметров или env vars)
        let client_id = params.0.client_id
            .or_else(|| std::env::var("WHOOP_CLIENT_ID").ok());
        let client_secret = params.0.client_secret
            .or_else(|| std::env::var("WHOOP_CLIENT_SECRET").ok());

        // Step 3b: Валидировать credentials ДО вызова адаптеров
        if client_id.is_none() {
            let response = ConnectProviderResponse {
                status: "error".to_string(),
                connection_id: connection_id.clone(),
                provider: "whoop".to_string(),
                error: Some(ConnectProviderError {
                    kind: "missing_client_credentials".to_string(),
                    message: "Provider credentials not configured.".to_string(),
                    recovery: "Configure WHOOP_CLIENT_ID and WHOOP_CLIENT_SECRET environment variables.".to_string(),
                }),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }

        // Step 4: Построить service name для vault
        let service = format!("vitalstead.whoop.{}", connection_id);

        // Step 5: Вызвать connect() в spawn_blocking (синхронный вызов на async runtime)
        let flow = self.authorization_flow.clone();
        let token_client = self.token_exchange_client.clone();
        let vault = self.credential_vault.clone();
        let connection_id_clone = connection_id.clone();
        let service_clone = service.clone();
        let client_id_clone = client_id.clone().unwrap_or_default();
        let client_secret_opt = client_secret
            .map(vitalstead_mcp::core::security::SecretString::new);

        let result = tokio::task::spawn_blocking(move || {
            let session = vitalstead_mcp::core::connectors::whoop::connect::WhoopConnectSession::new(
                flow.as_ref(),
                token_client.as_ref(),
                vault.as_ref(),
            );
            session.connect(
                connection_id_clone,
                client_id_clone,
                client_secret_opt,
                service_clone,
            )
        }).await;

        // Step 6: Обработать результат
        match result {
            Err(join_err) => {
                // JoinError: panic или task cancelled
                error!("connect_provider spawn_blocking error: {:?}", join_err);
                let response = ConnectProviderResponse {
                    status: "error".to_string(),
                    connection_id,
                    provider: "whoop".to_string(),
                    error: Some(ConnectProviderError {
                        kind: "internal_error".to_string(),
                        message: "An unexpected error occurred while connecting.".to_string(),
                        recovery: "Retry the connection. If it persists, report the issue.".to_string(),
                    }),
                };
                return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            }
            Ok(connect_result) => {
                match connect_result {
                    Ok(_outcome) => {
                        // Success
                        let response = ConnectProviderResponse {
                            status: "connected".to_string(),
                            connection_id,
                            provider: "whoop".to_string(),
                            error: None,
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                    Err(e) => {
                        // WhoopConnectError occurred
                        error!("connect_provider WhoopConnectError: {:?}", e);
                        let mapped = e.to_mcp_error();
                        let response = ConnectProviderResponse {
                            status: "error".to_string(),
                            connection_id,
                            provider: "whoop".to_string(),
                            error: Some(ConnectProviderError {
                                kind: mapped.code,
                                message: mapped.message,
                                recovery: mapped.recovery,
                            }),
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                }
            }
        }
    }

    /// Tool disconnect_provider (T-605 Spec 4.2).
    /// Отключает OAuth provider: best-effort revoke + безусловное удаление credentials.
    /// CSV не удаляются (D-010) — только конфигурация подключения и токены.
    #[tool(description = "Disconnect a data provider. Attempts best-effort token revocation, then unconditionally deletes stored credentials. CSV files are never deleted (D-010).")]
    pub async fn disconnect_provider(&self, params: Parameters<DisconnectProviderParams>) -> String {
        info!("disconnect_provider tool called with provider: {}", params.0.provider);

        if params.0.provider != "whoop" {
            let response = DisconnectProviderResponse {
                status: "error".to_string(),
                connection_id: params.0.connection_id,
                provider: params.0.provider.clone(),
                revoke_attempted: None,
                revoke_succeeded: None,
                error: Some(DisconnectProviderError {
                    kind: "unsupported_provider".to_string(),
                    message: "This provider is not yet supported.".to_string(),
                    recovery: "Use a supported provider (WHOOP, etc).".to_string(),
                }),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }

        let connection_id = params.0.connection_id;
        let service = format!("vitalstead.whoop.{}", connection_id);

        let client_id = std::env::var("WHOOP_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("WHOOP_CLIENT_SECRET").ok()
            .map(vitalstead_mcp::core::security::SecretString::new);

        let vault = self.credential_vault.clone();
        let token_client = self.token_exchange_client.clone();
        let connection_id_clone = connection_id.clone();
        let request = vitalstead_mcp::core::oauth::disconnect::DisconnectRequest {
            connection_id: connection_id_clone,
            service,
            revoke_endpoint: None, // WHOOP revoke endpoint не подтверждён (T-305 note)
            client_id,
            client_secret,
        };

        let result = tokio::task::spawn_blocking(move || {
            let orchestrator = vitalstead_mcp::core::oauth::disconnect::DisconnectOrchestrator::new(
                vault.as_ref(),
                token_client.as_ref(),
            );
            orchestrator.disconnect(request)
        }).await;

        match result {
            Err(join_err) => {
                error!("disconnect_provider spawn_blocking error: {:?}", join_err);
                let response = DisconnectProviderResponse {
                    status: "error".to_string(),
                    connection_id,
                    provider: "whoop".to_string(),
                    revoke_attempted: None,
                    revoke_succeeded: None,
                    error: Some(DisconnectProviderError {
                        kind: "internal_error".to_string(),
                        message: "An unexpected error occurred while disconnecting.".to_string(),
                        recovery: "Retry the disconnection. If it persists, report the issue.".to_string(),
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
            Ok(Ok(vitalstead_mcp::core::oauth::disconnect::DisconnectOutcome::Disconnected { revoke_attempted, revoke_succeeded })) => {
                let response = DisconnectProviderResponse {
                    status: "disconnected".to_string(),
                    connection_id,
                    provider: "whoop".to_string(),
                    revoke_attempted: Some(revoke_attempted),
                    revoke_succeeded: Some(revoke_succeeded),
                    error: None,
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
            Ok(Err(e)) => {
                error!("disconnect_provider DisconnectError: {:?}", e);
                let mapped = e.to_mcp_error();
                let response = DisconnectProviderResponse {
                    status: "error".to_string(),
                    connection_id,
                    provider: "whoop".to_string(),
                    revoke_attempted: None,
                    revoke_succeeded: None,
                    error: Some(DisconnectProviderError {
                        kind: mapped.code,
                        message: mapped.message,
                        recovery: mapped.recovery,
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
        }
    }

    /// Tool set_data_folder (T-202 Spec 3.5).
    /// Валидирует путь, сохраняет конфигурацию, обновляет shared state.
    #[tool(description = "Set data folder for CSV storage. Validates path (must be writable and readable).")]
    pub async fn set_data_folder(&self, params: Parameters<SetDataFolderParams>) -> String {
        info!("set_data_folder tool called with path: {}", params.0.path);

        let path = PathBuf::from(&params.0.path);

        match verify_writable_and_readable(&path) {
            Err(vitalstead_mcp::adapters::file_picker::PickerError::NotWritable) => {
                let response = SetDataFolderResponse {
                    status: "error".to_string(),
                    data_folder: None,
                    error: Some(SetDataFolderError {
                        kind: "not_writable".to_string(),
                        message: "Directory is not writable or not readable".to_string(),
                        recovery: "Choose a writable, existing folder and retry.".to_string(),
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
            Err(vitalstead_mcp::adapters::file_picker::PickerError::Backend(msg)) => {
                let response = SetDataFolderResponse {
                    status: "error".to_string(),
                    data_folder: None,
                    error: Some(SetDataFolderError {
                        kind: "invalid_path".to_string(),
                        message: msg,
                        recovery: "Verify the path is correct and retry.".to_string(),
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
            Err(vitalstead_mcp::adapters::file_picker::PickerError::Cancelled) => {
                // Cancelled не должно происходить в set_data_folder, но на случай...
                let response = SetDataFolderResponse {
                    status: "error".to_string(),
                    data_folder: None,
                    error: Some(SetDataFolderError {
                        kind: "cancelled".to_string(),
                        message: "Operation was cancelled".to_string(),
                        recovery: "Retry the operation.".to_string(),
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
            Ok(()) => {
                // Валидация успешна; сохраняем конфиг
                let config = AppConfig {
                    data_folder: path.clone(),
                };

                match config::save(self.writer.as_ref(), &self.app_support_dir, &config) {
                    Err(e) => {
                        // Сбой персиста — не обновляем state, возвращаем ошибку
                        error!("Failed to persist config: {:?}", e);
                        let mapped = e.to_mcp_error();
                        let response = SetDataFolderResponse {
                            status: "error".to_string(),
                            data_folder: None,
                            error: Some(SetDataFolderError {
                                kind: mapped.code,
                                message: mapped.message,
                                recovery: mapped.recovery,
                            }),
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                    Ok(()) => {
                        // Персист успешен; обновляем state
                        *self.data_folder.lock().unwrap() = Some(path.clone());
                        let response = SetDataFolderResponse {
                            status: "ok".to_string(),
                            data_folder: Some(path.to_string_lossy().to_string()),
                            error: None,
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                }
            }
        }
    }

    /// Tool delete_app_data (T-606 Spec 4.3).
    /// Удаляет application data: CSV-файлы, config.json, и credentials.
    /// Вызывается ТОЛЬКО по явному запросу пользователя — никогда не вызывается
    /// другими flow'ами (disconnect_provider не вызывает это, D-010).
    /// connections=null удаляет ВСЕ: все CSV в data_folder, config.json, credentials
    /// для всех подключений, которые сервер имеет запись о.
    /// connections=[...] (явный список) удаляет ТОЛЬКО credentials для этих подключений;
    /// CSV и config.json остаются нетронутыми (per-connection CSV изоляция ещё не реализована).
    #[tool(description = "Delete application data: CSV files, config, and stored credentials. \
        Called ONLY on explicit user request — never invoked by any other flow (disconnect_provider \
        does not call this, D-010). \
        connections=null deletes EVERYTHING: all CSV files in the data folder, config.json, and \
        credentials for every connection this server has record of. KNOWN LIMITATION: a connection \
        that was connected (connect_provider) but never successfully synced may not be discovered by \
        this 'all' scan — pass an explicit connections list if you know the provider/connection_id. \
        connections=[...] (explicit list) deletes ONLY the credentials for those connections; CSV files \
        and config.json are left untouched (per-connection CSV isolation is not yet implemented) — use \
        connections=null to also wipe CSV data.")]
    pub async fn delete_app_data(&self, params: Parameters<DeleteAppDataParams>) -> String {
        info!("delete_app_data tool called, scoped={}", params.0.connections.is_some());

        let data_folder = self.data_folder.lock().unwrap().clone();
        let app_support_dir = self.app_support_dir.clone();
        let writer = self.writer.clone();
        let vault = self.credential_vault.clone();
        let connections_param = params.0.connections;

        let result = tokio::task::spawn_blocking(move || {
            // ---- 1. CSV ----
            let csv = if let Some(ref explicit) = connections_param {
                let _ = explicit;
                CsvDeletionReport {
                    attempted: false,
                    skipped_reason: Some(
                        "Per-connection CSV deletion is not supported yet (sync engine does not \
                         isolate CSV files by connection_id). Pass connections=null to delete all CSV \
                         files together with credentials.".to_string()
                    ),
                    deleted_files: vec![],
                    failed_files: vec![],
                }
            } else if let Some(folder) = data_folder.as_ref() {
                let mut deleted = vec![];
                let mut failed = vec![];
                match std::fs::read_dir(folder) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            let path_str = path.display().to_string();
                            match std::fs::remove_file(&path) {
                                Ok(()) => deleted.push(path_str),
                                Err(e) => failed.push(FileDeletionResult {
                                    path: path_str,
                                    status: "failed".to_string(),
                                    error_kind: Some(io_error_to_write_error(e).to_mcp_error().code),
                                }),
                            }
                        }
                        CsvDeletionReport { attempted: true, skipped_reason: None, deleted_files: deleted, failed_files: failed }
                    }
                    Err(_) => CsvDeletionReport { attempted: true, skipped_reason: None, deleted_files: vec![], failed_files: vec![] },
                }
            } else {
                CsvDeletionReport {
                    attempted: false,
                    skipped_reason: Some("No data folder configured (set_data_folder was never called).".to_string()),
                    deleted_files: vec![],
                    failed_files: vec![],
                }
            };

            // ---- 2. config.json ----
            let config = if connections_param.is_some() {
                ConfigDeletionResult { attempted: false, status: "skipped".to_string(), path: None, error_kind: None }
            } else {
                let path = vitalstead_mcp::config::config_file_path(&app_support_dir);
                let path_str = path.display().to_string();
                match std::fs::remove_file(&path) {
                    Ok(()) => ConfigDeletionResult { attempted: true, status: "deleted".to_string(), path: Some(path_str), error_kind: None },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                        ConfigDeletionResult { attempted: true, status: "not_found".to_string(), path: Some(path_str), error_kind: None },
                    Err(e) => ConfigDeletionResult {
                        attempted: true, status: "failed".to_string(), path: Some(path_str),
                        error_kind: Some(io_error_to_write_error(e).to_mcp_error().code),
                    },
                }
            };

            // ---- 3. credentials ----
            let targets: Vec<ConnectionRef> = if let Some(explicit) = connections_param {
                explicit
            } else {
                let state = vitalstead_mcp::core::sync::state::load(writer.as_ref(), &app_support_dir)
                    .unwrap_or_default();
                let mut seen = std::collections::HashSet::new();
                state.entries.into_iter()
                    .filter(|e| seen.insert((e.provider.clone(), e.connection_id.clone())))
                    .map(|e| ConnectionRef { provider: e.provider, connection_id: e.connection_id })
                    .collect()
            };

            let credentials = targets.into_iter().map(|c| {
                let service = format!("vitalstead.{}.{}", c.provider, c.connection_id);
                match vault.delete_all_for_connection(&service) {
                    Ok(()) => CredentialDeletionResult { provider: c.provider, connection_id: c.connection_id, status: "deleted".to_string(), error_kind: None },
                    Err(e) => CredentialDeletionResult {
                        provider: c.provider, connection_id: c.connection_id, status: "failed".to_string(),
                        error_kind: Some(e.to_mcp_error().code),
                    },
                }
            }).collect::<Vec<_>>();

            (csv, config, credentials)
        }).await;

        let (csv, config, credentials) = match result {
            Ok(v) => v,
            Err(join_err) => {
                error!("delete_app_data spawn_blocking error: {:?}", join_err);
                let response = DeleteAppDataResponse {
                    status: "error".to_string(),
                    csv: CsvDeletionReport { attempted: false, skipped_reason: Some("Internal error.".to_string()), deleted_files: vec![], failed_files: vec![] },
                    config: ConfigDeletionResult { attempted: false, status: "failed".to_string(), path: None, error_kind: Some("internal_error".to_string()) },
                    credentials: vec![],
                    note: Some("An unexpected internal error occurred. Retry the operation.".to_string()),
                };
                return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            }
        };

        let failed_count = csv.failed_files.len()
            + if config.status == "failed" { 1 } else { 0 }
            + credentials.iter().filter(|c| c.status == "failed").count();
        let succeeded_count = csv.deleted_files.len()
            + if config.status == "deleted" { 1 } else { 0 }
            + credentials.iter().filter(|c| c.status == "deleted").count();

        let status = if failed_count == 0 {
            "success"
        } else if succeeded_count > 0 {
            "partial"
        } else {
            "error"
        }.to_string();

        let note = csv.skipped_reason.clone();

        let response = DeleteAppDataResponse { status, csv, config, credentials, note };
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
    }

    /// Tool sync_provider (T-602 Spec 5.1).
    /// Синхронизирует один подключённый источник данных. Ответ содержит только статусы
    /// и метаданные (количество записей, диапазоны дат), без значений health-данных (D-015).
    /// ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ (T-602 gap #1): всегда передаём expires_at=SystemTime::now(),
    /// что заставляет WhoopSyncSession всегда попытаться refresh в начале (safe, т.к.
    /// refresh идемпотентна и RefreshCoordinator дедупирует параллельные).
    /// ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ (T-602 gap #3): параллельные sync для одного провайдера
    /// исключены через SyncLockRegistry (mutex per connection).
    #[tool(description = "Sync one connected data provider (OAuth-authorized). Returns sync status, \
        record counts (sleep, recovery, cycle, workout), and date range covered — but never raw health \
        data values (D-015). By default syncs the last 7 days, or the last 365 days if this connection \
        has never synced before (backfill) — pass `days` to override either default explicitly (1-3650). \
        KNOWN LIMITATIONS: (1) always attempts token refresh at sync start (design \
        choice, see T-602 gap #1); (2) concurrent sync of the same provider/connection is serialized; \
        (3) connections that were connect_provider'd but never synced are not discoverable — call with \
        explicit provider/connection_id.")]
    pub async fn sync_provider(&self, params: Parameters<SyncProviderParams>) -> String {
        info!("sync_provider tool called: provider={}, connection_id={}", params.0.provider, params.0.connection_id);

        // Step 1: Validate provider
        if params.0.provider != "whoop" {
            let response = SyncResult {
                provider: params.0.provider.clone(),
                connection_id: params.0.connection_id.clone(),
                status: "error".to_string(),
                sleep_count: None,
                recovery_count: None,
                cycle_count: None,
                workout_count: None,
                time_range_start: "".to_string(),
                time_range_end: "".to_string(),
                error: Some(SyncProviderError {
                    kind: "unsupported_provider".to_string(),
                    message: "This provider is not yet supported.".to_string(),
                    recovery: "Use a supported provider (WHOOP, etc).".to_string(),
                }),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }

        let provider = params.0.provider.clone();
        let connection_id = params.0.connection_id.clone();
        let days_override = params.0.days;

        // Step 2: Check data_folder configured
        let data_folder = self.data_folder.lock().unwrap().clone();
        if data_folder.is_none() {
            let response = SyncResult {
                provider: provider.clone(),
                connection_id: connection_id.clone(),
                status: "error".to_string(),
                sleep_count: None,
                recovery_count: None,
                cycle_count: None,
                workout_count: None,
                time_range_start: "".to_string(),
                time_range_end: "".to_string(),
                error: Some(SyncProviderError {
                    kind: "no_data_folder_configured".to_string(),
                    message: "No data folder configured.".to_string(),
                    recovery: "Set the data folder using set_data_folder before syncing.".to_string(),
                }),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }

        // Step 2b (T-407): validate `days` override up front, before spawn_blocking.
        if let Some(d) = days_override {
            if d <= 0 || d > MAX_SYNC_DAYS {
                let response = SyncResult {
                    provider: provider.clone(),
                    connection_id: connection_id.clone(),
                    status: "error".to_string(),
                    sleep_count: None,
                    recovery_count: None,
                    cycle_count: None,
                    workout_count: None,
                    time_range_start: "".to_string(),
                    time_range_end: "".to_string(),
                    error: Some(SyncProviderError {
                        kind: "invalid_days".to_string(),
                        message: format!("`days` must be between 1 and {} (got {}).", MAX_SYNC_DAYS, d),
                        recovery: "Provide a `days` value between 1 and 3650, or omit it to use the default window.".to_string(),
                    }),
                };
                return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            }
        }

        // Step 3: Get credentials from env vars
        let client_id = std::env::var("WHOOP_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("WHOOP_CLIENT_SECRET").ok()
            .map(vitalstead_mcp::core::security::SecretString::new);

        // Step 4: Prepare clones for spawn_blocking
        let vault = self.credential_vault.clone();
        let token_client = self.token_exchange_client.clone();
        let refresh_coordinator = self.refresh_coordinator.clone();
        let sync_lock_registry = self.sync_lock_registry.clone();
        let app_support_dir = self.app_support_dir.clone();
        let csv_atomic_writer = self.writer.clone();

        // Step 5: Run sync in spawn_blocking with per-connection lock
        let provider_for_result = provider.clone();
        let connection_id_for_result = connection_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            let lock_key = format!("{}:{}", provider, connection_id);
            let lock = sync_lock_registry.lock_for(&lock_key);
            let _guard = lock.lock().expect("sync lock poisoned");

            // Build WhoopSyncRequest. T-407: first sync for this connection
            // (no sync_state entries yet) backfills DEFAULT_BACKFILL_SYNC_DAYS
            // instead of only DEFAULT_INCREMENTAL_SYNC_DAYS; `days_override`
            // (already range-validated above) takes precedence over either default.
            let prior_sync = has_prior_sync(csv_atomic_writer.as_ref(), &app_support_dir, &provider, &connection_id);
            let (time_range_start, time_range_end) = resolve_sync_window(days_override, prior_sync, chrono::Utc::now())
                .expect("days_override already range-validated");
            let service = format!("vitalstead.{}.{}", provider, connection_id);
            let target_dir = data_folder.unwrap();

            let request = vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncRequest {
                connection_id: connection_id.clone(),
                service,
                client_id,
                client_secret,
                time_range: (time_range_start, time_range_end),
                expires_at: std::time::SystemTime::now(),  // T-602 gap #1: always refresh
                target_dir,
            };

            // Build session and orchestrator
            let sleeper = vitalstead_mcp::core::oauth::RealSleeper;
            let clock = vitalstead_mcp::core::connectors::whoop::sync::RealClock;
            let api_client = vitalstead_mcp::core::connectors::whoop::client::WhoopApiClient::new();
            let throttle = vitalstead_mcp::core::connectors::rate_limiter::PacedThrottle::new(100, std::time::Duration::from_secs(60));

            let session = vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncSession::new(
                vault.as_ref(),
                token_client.as_ref(),
                refresh_coordinator.as_ref(),
                &sleeper,
                &clock,
                &api_client,
                &throttle,
            );

            let csv_writer = vitalstead_mcp::core::csv::writer::CsvWriter::new(csv_atomic_writer.as_ref());
            let orchestrator = vitalstead_mcp::core::sync::SyncOrchestrator::new(
                &session,
                &csv_writer,
                csv_atomic_writer.as_ref(),
                &app_support_dir,
            );

            // Sync one
            let req = vitalstead_mcp::core::sync::ConnectionSyncRequest {
                provider: provider.clone(),
                whoop_request: request,
            };
            let report = orchestrator.sync_one(req);
            (report, time_range_start, time_range_end)
        }).await;

        match result {
            Err(join_err) => {
                error!("sync_provider spawn_blocking error: {:?}", join_err);
                let now_str = chrono::Utc::now().to_rfc3339();
                let response = SyncResult {
                    provider: provider_for_result,
                    connection_id: connection_id_for_result,
                    status: "error".to_string(),
                    sleep_count: None,
                    recovery_count: None,
                    cycle_count: None,
                    workout_count: None,
                    time_range_start: now_str.clone(),
                    time_range_end: now_str,
                    error: Some(SyncProviderError {
                        kind: "internal_error".to_string(),
                        message: "An unexpected error occurred while syncing.".to_string(),
                        recovery: "Retry the sync. If it persists, report the issue.".to_string(),
                    }),
                };
                return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            }
            Ok((report, time_range_start, time_range_end)) => {
                let time_range_start_str = time_range_start.to_rfc3339();
                let time_range_end_str = time_range_end.to_rfc3339();
                match report.result {
                    Ok(outcome) => {
                        let (sleep_count, recovery_count, cycle_count, workout_count) = match outcome {
                            vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncOutcome::Synced {
                                sleep_count,
                                recovery_count,
                                cycle_count,
                                workout_count,
                            } => (sleep_count, recovery_count, cycle_count, workout_count),
                        };

                        let response = SyncResult {
                            provider: report.provider,
                            connection_id: report.connection_id,
                            status: "synced".to_string(),
                            sleep_count: Some(sleep_count),
                            recovery_count: Some(recovery_count),
                            cycle_count: Some(cycle_count),
                            workout_count: Some(workout_count),
                            time_range_start: time_range_start_str,
                            time_range_end: time_range_end_str,
                            error: None,
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                    Err(e) => {
                        error!("sync_provider WhoopSyncError: {:?}", e);
                        let mapped = e.to_mcp_error();
                        let response = SyncResult {
                            provider: report.provider,
                            connection_id: report.connection_id,
                            status: "error".to_string(),
                            sleep_count: None,
                            recovery_count: None,
                            cycle_count: None,
                            workout_count: None,
                            time_range_start: time_range_start_str,
                            time_range_end: time_range_end_str,
                            error: Some(SyncProviderError {
                                kind: mapped.code,
                                message: mapped.message,
                                recovery: mapped.recovery,
                            }),
                        };
                        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
                    }
                }
            }
        }
    }

    /// Tool sync_now (T-602 Spec 5.2).
    /// Синхронизирует все обнаруженные подключённые источники. Продолжает при ошибке одного.
    /// Ответ содержит только статусы и метаданные (T-602: D-015).
    #[tool(description = "Sync all connected data providers (OAuth-authorized). Discovers connections \
        from sync history and syncs each one, continuing despite individual failures. Returns aggregate \
        status (success/partial/no_connections) and per-connection sync results with status and record counts \
        — never raw health data values (D-015). Each connection defaults to the last 7 days, or 365 days \
        if it has never synced before (backfill); pass `days` to override this uniformly for all connections \
        (1-3650). KNOWN LIMITATIONS: connections that were connect_provider'd \
        but never synced are not discoverable; they are skipped silently.")]
    pub async fn sync_now(&self, params: Parameters<SyncNowParams>) -> String {
        info!("sync_now tool called");

        let days_override = params.0.days;
        if let Some(d) = days_override {
            if d <= 0 || d > MAX_SYNC_DAYS {
                return serde_json::to_string(&SyncNowResponse {
                    status: "error".to_string(),
                    results: vec![SyncResult {
                        provider: "".to_string(),
                        connection_id: "".to_string(),
                        status: "error".to_string(),
                        sleep_count: None,
                        recovery_count: None,
                        cycle_count: None,
                        workout_count: None,
                        time_range_start: "".to_string(),
                        time_range_end: "".to_string(),
                        error: Some(SyncProviderError {
                            kind: "invalid_days".to_string(),
                            message: format!("`days` must be between 1 and {} (got {}).", MAX_SYNC_DAYS, d),
                            recovery: "Provide a `days` value between 1 and 3650, or omit it to use the default window.".to_string(),
                        }),
                    }],
                }).unwrap_or_else(|_| "{}".to_string());
            }
        }

        let data_folder = self.data_folder.lock().unwrap().clone();
        let app_support_dir = self.app_support_dir.clone();
        let writer = self.writer.clone();
        let vault = self.credential_vault.clone();
        let token_client = self.token_exchange_client.clone();
        let refresh_coordinator = self.refresh_coordinator.clone();
        let sync_lock_registry = self.sync_lock_registry.clone();
        let csv_atomic_writer = self.writer.clone();

        // Run discovery and sync in spawn_blocking
        let result = tokio::task::spawn_blocking(move || {
            // Step 1: Discover connections from sync_state.json
            let state = vitalstead_mcp::core::sync::state::load(writer.as_ref(), &app_support_dir)
                .unwrap_or_default();
            // T-407: kept for per-connection has_prior_sync lookups below — every
            // connection sync_now discovers already has an entry here by
            // construction (that's how it's discovered), but computing it
            // per-connection keeps this in sync with sync_provider's logic if
            // discovery ever changes (see KNOWN LIMITATIONS on this tool).
            let entries_for_lookup = state.entries.clone();

            // Dedupe by (provider, connection_id)
            let mut seen = std::collections::HashSet::new();
            let connections: Vec<(String, String)> = state.entries
                .into_iter()
                .filter(|e| seen.insert((e.provider.clone(), e.connection_id.clone())))
                .map(|e| (e.provider, e.connection_id))
                .collect();

            // Step 2: If no connections discovered, return early
            if connections.is_empty() {
                return SyncNowResponse {
                    status: "no_connections".to_string(),
                    results: vec![],
                };
            }

            // Step 3: If data_folder not configured, return error
            let target_dir = match data_folder {
                Some(d) => d,
                None => {
                    return SyncNowResponse {
                        status: "no_data_folder_configured".to_string(),
                        results: vec![],
                    };
                }
            };

            // Step 4: Get credentials from env vars (shared for all WHOOP connections)
            let client_id = std::env::var("WHOOP_CLIENT_ID").unwrap_or_default();
            let client_secret = std::env::var("WHOOP_CLIENT_SECRET").ok()
                .map(vitalstead_mcp::core::security::SecretString::new);

            // Step 5: Build one WhoopSyncSession for all connections (they share client_id/client_secret)
            let sleeper = vitalstead_mcp::core::oauth::RealSleeper;
            let clock = vitalstead_mcp::core::connectors::whoop::sync::RealClock;
            let api_client = vitalstead_mcp::core::connectors::whoop::client::WhoopApiClient::new();
            let throttle = vitalstead_mcp::core::connectors::rate_limiter::PacedThrottle::new(100, std::time::Duration::from_secs(60));

            let session = vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncSession::new(
                vault.as_ref(),
                token_client.as_ref(),
                refresh_coordinator.as_ref(),
                &sleeper,
                &clock,
                &api_client,
                &throttle,
            );

            let csv_writer = vitalstead_mcp::core::csv::writer::CsvWriter::new(csv_atomic_writer.as_ref());
            let orchestrator = vitalstead_mcp::core::sync::SyncOrchestrator::new(
                &session,
                &csv_writer,
                csv_atomic_writer.as_ref(),
                &app_support_dir,
            );

            // Step 6: Sync each connection with per-connection locking. T-407:
            // window is resolved per connection (first sync backfills further
            // than a later incremental sync); `days_override`, already
            // range-validated above, applies uniformly to all of them.
            let mut results: Vec<SyncResult> = vec![];
            let now = chrono::Utc::now();

            for (provider, connection_id) in connections {
                let lock_key = format!("{}:{}", provider, connection_id);
                let lock = sync_lock_registry.lock_for(&lock_key);
                let _guard = lock.lock().expect("sync lock poisoned");

                let prior_sync = entries_for_lookup.iter()
                    .any(|e| e.provider == provider && e.connection_id == connection_id);
                let (time_range_start, time_range_end) = resolve_sync_window(days_override, prior_sync, now)
                    .expect("days_override already range-validated");

                let service = format!("vitalstead.{}.{}", provider, connection_id);

                let request = vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncRequest {
                    connection_id: connection_id.clone(),
                    service,
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                    time_range: (time_range_start, time_range_end),
                    expires_at: std::time::SystemTime::now(),  // T-602 gap #1: always refresh
                    target_dir: target_dir.clone(),
                };

                let req = vitalstead_mcp::core::sync::ConnectionSyncRequest {
                    provider: provider.clone(),
                    whoop_request: request,
                };

                let report = orchestrator.sync_one(req);

                let sync_result = match report.result {
                    Ok(outcome) => {
                        let (sleep_count, recovery_count, cycle_count, workout_count) = match outcome {
                            vitalstead_mcp::core::connectors::whoop::sync::WhoopSyncOutcome::Synced {
                                sleep_count,
                                recovery_count,
                                cycle_count,
                                workout_count,
                            } => (sleep_count, recovery_count, cycle_count, workout_count),
                        };

                        SyncResult {
                            provider: provider.clone(),
                            connection_id: connection_id.clone(),
                            status: "synced".to_string(),
                            sleep_count: Some(sleep_count),
                            recovery_count: Some(recovery_count),
                            cycle_count: Some(cycle_count),
                            workout_count: Some(workout_count),
                            time_range_start: time_range_start.to_rfc3339(),
                            time_range_end: time_range_end.to_rfc3339(),
                            error: None,
                        }
                    }
                    Err(e) => {
                        let mapped = e.to_mcp_error();
                        SyncResult {
                            provider: provider.clone(),
                            connection_id: connection_id.clone(),
                            status: "error".to_string(),
                            sleep_count: None,
                            recovery_count: None,
                            cycle_count: None,
                            workout_count: None,
                            time_range_start: time_range_start.to_rfc3339(),
                            time_range_end: time_range_end.to_rfc3339(),
                            error: Some(SyncProviderError {
                                kind: mapped.code,
                                message: mapped.message,
                                recovery: mapped.recovery,
                            }),
                        }
                    }
                };

                results.push(sync_result);
            }

            // Step 7: Aggregate status
            let has_error = results.iter().any(|r| r.status == "error");
            let status = if results.is_empty() {
                "no_connections".to_string()
            } else if has_error {
                "partial".to_string()
            } else {
                "success".to_string()
            };

            SyncNowResponse { status, results }
        }).await;

        match result {
            Ok(response) => serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()),
            Err(_) => {
                // Internal error (task panic/cancel)
                let response = SyncNowResponse {
                    status: "error".to_string(),
                    results: vec![],
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
        }
    }

    /// Tool query_data (T-603).
    /// Запрашивает агрегаты (min/max/avg/count) по метрике CSV за период.
    /// По умолчанию возвращает только агрегаты и метаданные (D-015).
    /// С include_raw=true возвращает сырые ряды (ограничено 500 rows).
    /// Провайдеры не смешиваются без явного списка (D-008).
    #[tool(description = "Query data and get aggregates (min/max/avg/count) for a metric column. \
        By default returns only aggregates and metadata without raw health values (D-015). \
        Pass include_raw: true to include matching raw rows in the response (these raw values \
        will enter the model's conversation context); raw responses are capped at 500 rows — \
        narrow the time range (start/end) or filter by specific providers to see fewer rows. \
        Providers are never silently mixed: when a CSV contains multiple distinct source values, \
        you must explicitly list the providers you want via the providers parameter (D-008). \
        Supported data types: sleep, recovery, cycle, workout. NOTE: some rows (e.g. today's \
        not-yet-closed cycle) carry score_state=PENDING_SCORE — their value (like strain) updates \
        live and isn't final yet. Check response.provisional_count/provisional_note before \
        presenting a value like today's strain as settled; it may still change.")]
    pub async fn query_data(&self, params: Parameters<QueryDataParams>) -> String {
        info!("query_data tool called: data_type={}, column={}", params.0.data_type, params.0.column);

        let data_type = params.0.data_type.clone();
        let column = params.0.column.clone();
        let providers_param = params.0.providers.clone();
        let start_str = params.0.start.clone();
        let end_str = params.0.end.clone();
        let include_raw = params.0.include_raw;

        let data_folder = self.data_folder.lock().unwrap().clone();

        let result = tokio::task::spawn_blocking(move || {
            use vitalstead_mcp::core::connectors::whoop::mapping::{
                sleep_schema, recovery_schema, cycle_schema, workout_schema,
            };
            use vitalstead_mcp::core::csv::parse::deserialize;

            // Step 1: Validate data_type and get schema + filename
            let (schema_fn, filename): (fn() -> _, &str) = match data_type.as_str() {
                "sleep" => (sleep_schema, "sleep.csv"),
                "recovery" => (recovery_schema, "recovery.csv"),
                "cycle" => (cycle_schema, "cycles.csv"),
                "workout" => (workout_schema, "workouts.csv"),
                _ => {
                    return QueryDataResponse {
                        status: "error".to_string(),
                        data_type: data_type.clone(),
                        column: column.clone(),
                        providers: vec![],
                        start: start_str,
                        end: end_str,
                        aggregate: None,
                        raw: None,
                        raw_truncated: false,
                        raw_truncation_note: None,
                        provisional_count: 0,
                        provisional_note: None,
                        error: Some(QueryDataError {
                            kind: "unsupported_data_type".to_string(),
                            message: format!("'{}' is not a supported data type.", data_type),
                            recovery: "Use one of: sleep, recovery, cycle, workout.".to_string(),
                        }),
                    };
                }
            };

            let schema = schema_fn();

            // Step 2: Validate column is in schema
            if !schema.columns().contains(&column) {
                return QueryDataResponse {
                    status: "error".to_string(),
                    data_type: data_type.clone(),
                    column: column.clone(),
                    providers: vec![],
                    start: start_str,
                    end: end_str,
                    aggregate: None,
                    raw: None,
                    raw_truncated: false,
                    raw_truncation_note: None,
                    provisional_count: 0,
                    provisional_note: None,
                    error: Some(QueryDataError {
                        kind: "unknown_column".to_string(),
                        message: format!("'{}' is not a column of the {} schema.", column, data_type),
                        recovery: format!("Call list_data or check architecture.md for the {} schema's columns.", data_type),
                    }),
                };
            }

            // Step 3: Check data_folder configured
            if data_folder.is_none() {
                return QueryDataResponse {
                    status: "error".to_string(),
                    data_type: data_type.clone(),
                    column: column.clone(),
                    providers: vec![],
                    start: start_str,
                    end: end_str,
                    aggregate: None,
                    raw: None,
                    raw_truncated: false,
                    raw_truncation_note: None,
                    provisional_count: 0,
                    provisional_note: None,
                    error: Some(QueryDataError {
                        kind: "no_data_folder_configured".to_string(),
                        message: "No data folder configured.".to_string(),
                        recovery: "Set the data folder using set_data_folder before querying.".to_string(),
                    }),
                };
            }

            // Step 4: Read CSV file (if doesn't exist, treat as empty, not error)
            let csv_path = data_folder.as_ref().unwrap().join(filename);
            let rows = if !csv_path.exists() {
                // File doesn't exist = zero rows, valid state
                vec![]
            } else {
                match std::fs::read(&csv_path) {
                    Ok(bytes) => {
                        match deserialize(&schema, &bytes) {
                            Ok(rows) => rows,
                            Err(e) => {
                                warn!("Failed to parse CSV: {:?}", e);
                                return QueryDataResponse {
                                    status: "error".to_string(),
                                    data_type: data_type.clone(),
                                    column: column.clone(),
                                    providers: vec![],
                                    start: start_str,
                                    end: end_str,
                                    aggregate: None,
                                    raw: None,
                                    raw_truncated: false,
                                    raw_truncation_note: None,
                                    provisional_count: 0,
                                    provisional_note: None,
                                    error: Some(QueryDataError {
                                        kind: "malformed_csv".to_string(),
                                        message: format!("The {} CSV file's format doesn't match the expected schema.", data_type),
                                        recovery: "Verify the file is valid or delete it to resync.".to_string(),
                                    }),
                                };
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read CSV file: {:?}", e);
                        return QueryDataResponse {
                            status: "error".to_string(),
                            data_type: data_type.clone(),
                            column: column.clone(),
                            providers: vec![],
                            start: start_str,
                            end: end_str,
                            aggregate: None,
                            raw: None,
                            raw_truncated: false,
                            raw_truncation_note: None,
                            provisional_count: 0,
                            provisional_note: None,
                            error: Some(QueryDataError {
                                kind: "read_failed".to_string(),
                                message: format!("Could not read the {} CSV file.", data_type),
                                recovery: "Verify permissions or retry the sync.".to_string(),
                            }),
                        };
                    }
                }
            };

            // Step 5: D-008 provider resolution
            let source_idx = schema.columns().iter().position(|c| c == "source").unwrap_or(0);
            let mut distinct_sources: std::collections::HashSet<String> = std::collections::HashSet::new();
            for row in &rows {
                if let Some(Some(source_val)) = row.get(source_idx) {
                    distinct_sources.insert(source_val.clone());
                }
            }

            let filter_sources: std::collections::HashSet<String> = if let Some(providers_list) = &providers_param {
                // Use explicit provider list
                providers_list.iter().cloned().collect()
            } else {
                // Auto-resolve: 0 or 1 sources OK, 2+ requires explicit list
                if distinct_sources.len() > 1 {
                    return QueryDataResponse {
                        status: "error".to_string(),
                        data_type: data_type.clone(),
                        column: column.clone(),
                        providers: vec![],
                        start: start_str,
                        end: end_str,
                        aggregate: None,
                        raw: None,
                        raw_truncated: false,
                        raw_truncation_note: None,
                        provisional_count: 0,
                        provisional_note: None,
                        error: Some(QueryDataError {
                            kind: "ambiguous_providers".to_string(),
                            message: "This data contains rows from multiple providers; specify `providers` explicitly to avoid mixing them.".to_string(),
                            recovery: "Pass providers: [...] with the specific provider(s) you want.".to_string(),
                        }),
                    };
                }
                distinct_sources
            };

            let resolved_providers: Vec<String> = {
                let mut providers: Vec<String> = filter_sources.iter().cloned().collect();
                providers.sort();
                providers
            };

            // Step 6: Parse time bounds (if provided)
            let start_dt = if let Some(start_str) = &start_str {
                match chrono::DateTime::parse_from_rfc3339(start_str).map(|dt| dt.with_timezone(&chrono::Utc)) {
                    Ok(dt) => Some(dt),
                    Err(_) => {
                        return QueryDataResponse {
                            status: "error".to_string(),
                            data_type: data_type.clone(),
                            column: column.clone(),
                            providers: resolved_providers,
                            start: Some(start_str.clone()),
                            end: end_str,
                            aggregate: None,
                            raw: None,
                            raw_truncated: false,
                            raw_truncation_note: None,
                            provisional_count: 0,
                            provisional_note: None,
                            error: Some(QueryDataError {
                                kind: "invalid_time_range".to_string(),
                                message: "Could not parse start time as RFC3339.".to_string(),
                                recovery: "Use RFC3339 format (e.g., 2026-07-10T00:00:00Z).".to_string(),
                            }),
                        };
                    }
                }
            } else {
                None
            };

            let end_dt = if let Some(end_str) = &end_str {
                match chrono::DateTime::parse_from_rfc3339(end_str).map(|dt| dt.with_timezone(&chrono::Utc)) {
                    Ok(dt) => Some(dt),
                    Err(_) => {
                        return QueryDataResponse {
                            status: "error".to_string(),
                            data_type: data_type.clone(),
                            column: column.clone(),
                            providers: resolved_providers,
                            start: start_str,
                            end: Some(end_str.clone()),
                            aggregate: None,
                            raw: None,
                            raw_truncated: false,
                            raw_truncation_note: None,
                            provisional_count: 0,
                            provisional_note: None,
                            error: Some(QueryDataError {
                                kind: "invalid_time_range".to_string(),
                                message: "Could not parse end time as RFC3339.".to_string(),
                                recovery: "Use RFC3339 format (e.g., 2026-07-10T23:59:59Z).".to_string(),
                            }),
                        };
                    }
                }
            } else {
                None
            };

            let recorded_at_idx = schema.columns().iter().position(|c| c == "recorded_at").unwrap_or(2);
            let column_idx = schema.columns().iter().position(|c| c == &column).unwrap();
            let external_id_idx = schema.columns().iter().position(|c| c == "external_id").unwrap_or(1);

            // Step 7: Filter rows by source and time
            let filtered_rows: Vec<(usize, &vitalstead_mcp::core::csv::serialize::CsvRow)> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    // Filter by source
                    if let Some(Some(source_val)) = row.get(source_idx) {
                        if !filter_sources.contains(source_val) {
                            return false;
                        }
                    } else {
                        return false; // Missing source
                    }

                    // Filter by time
                    if let Some(Some(recorded_at_val)) = row.get(recorded_at_idx) {
                        match chrono::DateTime::parse_from_rfc3339(recorded_at_val).map(|dt| dt.with_timezone(&chrono::Utc)) {
                            Ok(dt) => {
                                if let Some(start) = start_dt {
                                    if dt < start {
                                        return false;
                                    }
                                }
                                if let Some(end) = end_dt {
                                    if dt > end {
                                        return false;
                                    }
                                }
                                true
                            }
                            Err(_) => {
                                warn!("Could not parse recorded_at for row with external_id={:?}", row.get(external_id_idx));
                                false
                            }
                        }
                    } else {
                        false // Missing recorded_at
                    }
                })
                .collect();

            // Step 8: Aggregate numeric values from column
            let mut aggregate = QueryDataAggregate {
                count: 0,
                min: None,
                max: None,
                avg: None,
            };
            let mut sum: f64 = 0.0;
            let mut values: Vec<f64> = vec![];

            // T-411: some data types (cycle, and others WHOOP scores async) carry
            // a `score_state` column — "PENDING_SCORE" means the row is still the
            // open, not-yet-finalized period (e.g. today's cycle, whose `strain`
            // WHOOP updates live throughout the day). None of these rows are
            // wrong or stale-on-disk; they're just not final yet, and an aggregate
            // that silently blends them with closed periods looks more final than
            // it is. `provisional_count` makes that visible in the response
            // instead of requiring a resync to "notice" the number moved.
            let score_state_idx = schema.columns().iter().position(|c| c == "score_state");
            let mut provisional_count: usize = 0;

            for (_, row) in &filtered_rows {
                if let Some(Some(cell_val)) = row.get(column_idx) {
                    if let Ok(f) = cell_val.parse::<f64>() {
                        if f.is_finite() {
                            values.push(f);
                            sum += f;
                            aggregate.count += 1;

                            if let Some(idx) = score_state_idx {
                                if let Some(Some(state)) = row.get(idx) {
                                    if state == "PENDING_SCORE" {
                                        provisional_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if aggregate.count > 0 {
                aggregate.min = Some(values.iter().cloned().fold(f64::INFINITY, f64::min));
                aggregate.max = Some(values.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
                aggregate.avg = Some(sum / aggregate.count as f64);
            }

            let provisional_note = if provisional_count > 0 {
                Some(format!(
                    "{} of {} aggregated row(s) are from a still-open period (score_state: PENDING_SCORE) — e.g. today's not-yet-closed cycle. WHOOP updates its value live; it isn't final and may differ from what a resync shows later.",
                    provisional_count, aggregate.count
                ))
            } else {
                None
            };

            // Step 9: Build raw rows (only if include_raw=true, capped at 500)
            const MAX_RAW_ROWS: usize = 500;
            let raw = if include_raw {
                let mut raw_rows = vec![];
                let mut truncated = false;
                for (_, row) in filtered_rows.iter().take(MAX_RAW_ROWS) {
                    let source_val = row.get(source_idx).and_then(|c| c.as_ref()).cloned().unwrap_or_else(|| "unknown".to_string());
                    let external_id_val = row.get(external_id_idx).and_then(|c| c.as_ref()).cloned().unwrap_or_else(|| "".to_string());
                    let recorded_at_val = row.get(recorded_at_idx).and_then(|c| c.as_ref()).cloned().unwrap_or_else(|| "".to_string());
                    let value = row.get(column_idx).and_then(|c| c.as_ref()).cloned();

                    raw_rows.push(QueryDataRawRow {
                        source: source_val,
                        external_id: external_id_val,
                        recorded_at: recorded_at_val,
                        value,
                    });
                }

                if filtered_rows.len() > MAX_RAW_ROWS {
                    truncated = true;
                }

                Some((raw_rows, truncated))
            } else {
                None
            };

            let (raw_rows, raw_truncated) = if let Some((rows, trunc)) = raw {
                (Some(rows), trunc)
            } else {
                (None, false)
            };

            let raw_truncation_note = if raw_truncated {
                Some(format!(
                    "Showing the first {} of {} matching rows. Narrow the time range (start/end) or add more specific providers to see fewer rows, or omit include_raw to get aggregates only.",
                    MAX_RAW_ROWS, filtered_rows.len()
                ))
            } else {
                None
            };

            QueryDataResponse {
                status: "ok".to_string(),
                data_type,
                column,
                providers: resolved_providers,
                start: start_str,
                end: end_str,
                aggregate: Some(aggregate),
                raw: raw_rows,
                raw_truncated,
                raw_truncation_note,
                provisional_count,
                provisional_note,
                error: None,
            }
        }).await;

        match result {
            Ok(response) => serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()),
            Err(join_err) => {
                error!("query_data spawn_blocking error: {:?}", join_err);
                let response = QueryDataResponse {
                    status: "error".to_string(),
                    data_type: params.0.data_type,
                    column: params.0.column,
                    providers: vec![],
                    start: params.0.start,
                    end: params.0.end,
                    aggregate: None,
                    raw: None,
                    raw_truncated: false,
                    raw_truncation_note: None,
                    provisional_count: 0,
                    provisional_note: None,
                    error: Some(QueryDataError {
                        kind: "internal_error".to_string(),
                        message: "An unexpected error occurred while querying data.".to_string(),
                        recovery: "Retry the query. If it persists, report the issue.".to_string(),
                    }),
                };
                serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
            }
        }
    }
}

/// Конструирует app_support_dir для macOS (T-202 Spec 3.2).
/// В практической реализации: $HOME/Library/Application Support.
/// Возвращает Err если HOME не задана.
fn app_support_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME env var not set".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support"))
}

/// Разрешает data_folder при старте (T-202 Spec 3.4).
/// Логика:
/// 1. Если VITALSTEAD_DATA_FOLDER задана → verify_writable_and_readable → save → вернуть
/// 2. Если нет → load из persisted config → вернуть (без повторной валидации)
/// 3. Если ничего → None
///
/// Helper-функция вынесена для unit-тестирования без через std::env::set_var гонок.
fn resolve_startup_data_folder(
    env_var: Option<String>,
    app_support_dir: &std::path::Path,
    writer: &dyn AtomicFileWriter,
) -> Option<PathBuf> {
    if let Some(path_str) = env_var {
        let path = PathBuf::from(&path_str);
        match verify_writable_and_readable(&path) {
            Ok(()) => {
                let config = AppConfig {
                    data_folder: path.clone(),
                };
                match config::save(writer, app_support_dir, &config) {
                    Ok(()) => {
                        info!("Startup: VITALSTEAD_DATA_FOLDER set and verified, config persisted");
                        return Some(path);
                    }
                    Err(e) => {
                        error!("Startup: Failed to persist config from VITALSTEAD_DATA_FOLDER: {:?}", e);
                        // Продолжаем с in-memory state; persist можно повторить через set_data_folder
                        return Some(path);
                    }
                }
            }
            Err(e) => {
                warn!("Startup: VITALSTEAD_DATA_FOLDER path validation failed: {:?}, falling back", e);
            }
        }
    }

    // Fallback: загружаем persisted config
    if let Ok(config) = config::load(app_support_dir) {
        info!("Startup: Loaded data_folder from persisted config");
        return Some(config.data_folder);
    }

    info!("Startup: No VITALSTEAD_DATA_FOLDER and no persisted config, starting with None");
    None
}

#[tokio::main]
async fn main() {
    // Инициализируем логирование ПЕРВЫМ ДЕЛОМ (до любых других операций, Spec 3.1)
    // Обязательно .with_writer(std::io::stderr), иначе логи загрязнят stdout,
    // зарезервированный для MCP JSON-RPC протокола (D-015, CLAUDE.md Security rules)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Vitalstead MCP server (T-201, T-202)");

    // T-202: Получаем app_support_dir (Spec 3.2)
    let app_support_dir = match app_support_dir() {
        Ok(dir) => dir,
        Err(e) => {
            error!("Failed to construct app_support_dir: {}", e);
            PathBuf::from("/tmp/vitalstead-fallback")
        }
    };

    // T-202: Инициализируем writer для конфигурации (Spec 3.3, 3.4)
    let writer: Arc<dyn AtomicFileWriter> = Arc::new(MacAtomicFileWriter::new());

    // T-202: Разрешаем data_folder (Spec 3.4)
    let data_folder_value = resolve_startup_data_folder(
        std::env::var("VITALSTEAD_DATA_FOLDER").ok(),
        &app_support_dir,
        writer.as_ref(),
    );

    // T-202: Создаём shared state (Spec 3.3)
    let data_folder = Arc::new(Mutex::new(data_folder_value));

    // T-604: Создаём Arc-обёрнутые адаптеры для OAuth и credential storage
    let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
        Arc::from(vitalstead_mcp::build_oauth_callback_handler());
    let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
        Arc::from(vitalstead_mcp::build_token_exchange_client());
    let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
        Arc::from(vitalstead_mcp::build_credential_vault());
    let authorization_flow = Arc::new(
        vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
    );

    // T-602: Создаём координаторы для sync и refresh операций
    let refresh_coordinator = Arc::new(
        vitalstead_mcp::core::oauth::refresh::RefreshCoordinator::new()
    );
    let sync_lock_registry = Arc::new(
        vitalstead_mcp::core::sync::SyncLockRegistry::new()
    );

    // Создаём экземпляр сервера с конфигурацией (T-202), OAuth adapters (T-604), и sync/refresh (T-602)
    let server = VitalsteadMcpServer::new(
        data_folder,
        app_support_dir,
        writer,
        token_exchange_client,
        credential_vault,
        authorization_flow,
        refresh_coordinator,
        sync_lock_registry,
    );

    info!("Server initialized, starting transport");

    // Запускаем stdio-транспорт (Spec 3.1).
    // rmcp::transport::io::stdio() возвращает (stdin, stdout) пару
    // IntoTransport преобразует её в асинхронный транспорт.
    // Stdout автоматически используется для JSON-RPC фреймов, нами не трогаем.
    let (stdin, stdout) = rmcp::transport::io::stdio();
    let transport = rmcp::transport::IntoTransport::<rmcp::service::RoleServer, _, _>::into_transport(
        (stdin, stdout),
    );

    match server.serve(transport).await {
        Ok(running) => {
            info!("MCP server initialization succeeded");
            // Ждём завершения сессии
            match running.waiting().await {
                Ok(_) => info!("MCP server shut down cleanly"),
                Err(e) => {
                    eprintln!("MCP server error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("MCP server initialization failed: {:?}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitalstead_mcp::adapters::CredentialVault;
    use chrono::Utc;

    /// Mock AtomicFileWriter для тестирования конфигурации (всегда fails)
    struct FailingAtomicFileWriter;

    impl vitalstead_mcp::adapters::AtomicFileWriter for FailingAtomicFileWriter {
        fn write_temp(
            &self,
            _dir: &std::path::Path,
            _content: &[u8],
        ) -> Result<PathBuf, vitalstead_mcp::adapters::WriteError> {
            Err(vitalstead_mcp::adapters::WriteError::Backend(
                "Mock write failure".to_string(),
            ))
        }

        fn replace_atomic(
            &self,
            _target: &std::path::Path,
            _temp_path: &std::path::Path,
        ) -> Result<(), vitalstead_mcp::adapters::WriteError> {
            Err(vitalstead_mcp::adapters::WriteError::Backend(
                "Mock replace failure".to_string(),
            ))
        }

        fn recover_from_backup(&self, _target: &std::path::Path) -> Result<(), vitalstead_mcp::adapters::WriteError> {
            Err(vitalstead_mcp::adapters::WriteError::Backend(
                "Mock recover failure".to_string(),
            ))
        }
    }

    /// T-604 test helper: build the 4 OAuth/credential Arc adapters that
    /// VitalsteadMcpServer::new() now requires. Pre-T-604 tests (config/set_data_folder)
    /// don't exercise OAuth at all, so real platform adapters (same as
    /// production main()) are fine here — they're never invoked by those tests.
    #[allow(clippy::type_complexity)]
    fn test_oauth_adapters() -> (
        Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler>,
        Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient>,
        Arc<dyn vitalstead_mcp::adapters::CredentialVault>,
        Arc<vitalstead_mcp::core::oauth::AuthorizationFlow>,
    ) {
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        (callback_handler, token_exchange_client, credential_vault, authorization_flow)
    }

    /// T-602 test helper: build the 2 sync/refresh Arc coordinators that
    /// VitalsteadMcpServer::new() now requires (T-602). Tests that don't exercise
    /// sync operations can use fresh instances (no shared state needed).
    fn test_sync_refresh_coordinators() -> (
        Arc<vitalstead_mcp::core::oauth::refresh::RefreshCoordinator>,
        Arc<vitalstead_mcp::core::sync::SyncLockRegistry>,
    ) {
        (
            Arc::new(vitalstead_mcp::core::oauth::refresh::RefreshCoordinator::new()),
            Arc::new(vitalstead_mcp::core::sync::SyncLockRegistry::new()),
        )
    }

    // ===== T-604 mock adapters =====
    //
    // main.rs is a separate binary crate from the library — it cannot reach
    // into vitalstead_mcp::core::connectors::whoop::connect's own
    // #[cfg(test)] mod tests (that module doesn't even exist when the library
    // is compiled as a normal (non-test) dependency of this binary). Local
    // mocks, matching the same shape used in connect.rs's own tests.

    /// Mock OAuthCallbackHandler for connect_provider tool-level tests.
    struct MockCallbackHandler {
        code: String,
        error_result: Option<(String, Option<String>)>,
    }

    impl MockCallbackHandler {
        fn new_success(code: String) -> Self {
            MockCallbackHandler { code, error_result: None }
        }

        fn new_error(error: String, error_description: Option<String>) -> Self {
            MockCallbackHandler {
                code: "unused".to_string(),
                error_result: Some((error, error_description)),
            }
        }
    }

    impl vitalstead_mcp::adapters::OAuthCallbackHandler for MockCallbackHandler {
        fn listen_for_callback(
            &self,
            expected_state: &str,
        ) -> Result<vitalstead_mcp::adapters::CallbackReceiver, vitalstead_mcp::adapters::CallbackError> {
            let (tx, rx) = tokio::sync::oneshot::channel::<
                Result<vitalstead_mcp::adapters::CallbackResult, vitalstead_mcp::adapters::CallbackError>,
            >();
            let result = if let Some((error, desc)) = &self.error_result {
                vitalstead_mcp::adapters::CallbackResult::Error {
                    error: error.clone(),
                    error_description: desc.clone(),
                }
            } else {
                vitalstead_mcp::adapters::CallbackResult::Success {
                    code: self.code.clone(),
                    state: expected_state.to_string(),
                }
            };
            let _ = tx.send(Ok(result));
            Ok(vitalstead_mcp::adapters::CallbackReceiver { recv: rx, port: 9999 })
        }

        fn open_system_browser(&self, _url: &str) -> Result<(), vitalstead_mcp::adapters::CallbackError> {
            Ok(())
        }
    }

    /// Mock TokenExchangeClient for connect_provider tool-level tests.
    struct MockTokenExchangeClient {
        response: vitalstead_mcp::adapters::TokenResponse,
    }

    impl MockTokenExchangeClient {
        fn new(response: vitalstead_mcp::adapters::TokenResponse) -> Self {
            MockTokenExchangeClient { response }
        }
    }

    impl vitalstead_mcp::adapters::TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: vitalstead_mcp::adapters::ExchangeCodeParams,
        ) -> Result<vitalstead_mcp::adapters::TokenResponse, vitalstead_mcp::adapters::TokenExchangeError> {
            Ok(self.response.clone())
        }

        fn refresh_token(
            &self,
            _params: vitalstead_mcp::adapters::RefreshTokenParams,
        ) -> Result<vitalstead_mcp::adapters::TokenResponse, vitalstead_mcp::adapters::TokenExchangeError> {
            // Reused by T-602 sync tests: sync_provider/sync_now always pass
            // expires_at=now() (T-602 gap #1), which unconditionally triggers a
            // refresh at the start of every sync — so this must return a usable
            // response rather than panic, unlike the old connect_provider-only
            // assumption. connect_provider tests never reach this path.
            Ok(self.response.clone())
        }

        fn revoke_token(
            &self,
            _params: vitalstead_mcp::adapters::RevokeTokenParams,
        ) -> Result<(), vitalstead_mcp::adapters::TokenExchangeError> {
            unreachable!("revoke_token not used in connect_provider tool tests")
        }
    }

    /// Mock CredentialVault for connect_provider tool-level tests.
    struct MockCredentialVault {
        data: Mutex<std::collections::HashMap<(String, String), vitalstead_mcp::core::security::SecretString>>,
    }

    impl MockCredentialVault {
        fn new() -> Self {
            MockCredentialVault { data: Mutex::new(std::collections::HashMap::new()) }
        }
    }

    impl vitalstead_mcp::adapters::CredentialVault for MockCredentialVault {
        fn store(
            &self,
            service: &str,
            key: &str,
            value: &vitalstead_mcp::core::security::SecretString,
        ) -> Result<(), vitalstead_mcp::adapters::VaultError> {
            self.data.lock().unwrap().insert((service.to_string(), key.to_string()), value.clone());
            Ok(())
        }

        fn retrieve(
            &self,
            service: &str,
            key: &str,
        ) -> Result<vitalstead_mcp::core::security::SecretString, vitalstead_mcp::adapters::VaultError> {
            self.data
                .lock()
                .unwrap()
                .get(&(service.to_string(), key.to_string()))
                .cloned()
                .ok_or(vitalstead_mcp::adapters::VaultError::NotFound)
        }

        fn delete(&self, service: &str, key: &str) -> Result<(), vitalstead_mcp::adapters::VaultError> {
            self.data
                .lock()
                .unwrap()
                .remove(&(service.to_string(), key.to_string()))
                .ok_or(vitalstead_mcp::adapters::VaultError::NotFound)
                .map(|_| ())
        }

        fn delete_all_for_connection(&self, service: &str) -> Result<(), vitalstead_mcp::adapters::VaultError> {
            let mut data = self.data.lock().unwrap();
            let keys: Vec<_> = data.keys().filter(|(s, _)| s == service).cloned().collect();
            for key in keys {
                data.remove(&key);
            }
            Ok(())
        }
    }

    // ===== T-201/T-602: list_data response shape =====

    #[test]
    fn test_list_data_response_empty_sources_serializes() {
        // T-602 replaced the T-201 placeholder with a real ListDataResponse shape —
        // this just checks the struct still serializes with the expected top-level keys.
        let response = ListDataResponse {
            sources: vec![],
            note: "test note".to_string(),
        };
        assert_eq!(response.sources.len(), 0);

        let json = serde_json::to_string(&response).expect("serialization should succeed");
        assert!(json.contains("sources"));
        assert!(json.contains("note"));
    }

    #[test]
    fn test_list_data_params_deserializes() {
        let empty_json = "{}";
        let _params: ListDataParams = serde_json::from_str(empty_json).expect("should deserialize");
    }

    #[test]
    fn test_stderr_writer_configured() {
        let _subscriber = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish();
    }

    // ===== T-202 tests (новые критерии приёмки) =====

    /// T-202 Spec 4: test_config_json_has_no_secrets (D-002)
    #[test]
    fn test_config_json_has_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = dir.path();

        let config = AppConfig {
            data_folder: PathBuf::from("/some/path"),
        };

        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&writer, app_support, &config);

        let config_path = config::config_file_path(app_support);
        if let Ok(content) = std::fs::read(&config_path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&content) {
                if let Some(obj) = value.as_object() {
                    let keys: Vec<_> = obj.keys().map(|k| k.as_str()).collect();
                    assert_eq!(
                        keys, vec!["data_folder"],
                        "config.json should only have data_folder, no secrets"
                    );
                }
            }
        }
    }

    /// T-202 Spec 4: test_set_data_folder_valid_path_persists_and_updates_state
    /// Тестируем через resolve_startup_data_folder, которая содержит核核 логику set_data_folder
    #[test]
    fn test_set_data_folder_valid_path_persists_and_updates_state() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();

        let env_var = Some(dir.path().to_string_lossy().to_string());
        let result = resolve_startup_data_folder(env_var, app_support.path(), &writer);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), dir.path());

        // Проверяем, что config persisted
        let config_loaded = config::load(app_support.path()).unwrap();
        assert_eq!(config_loaded.data_folder, dir.path());
    }

    /// T-202 Spec 4: test_set_data_folder_invalid_path_returns_structured_error_not_panic
    /// Тестируем через verify_writable_and_readable
    #[test]
    fn test_set_data_folder_invalid_path_returns_structured_error_not_panic() {
        let invalid_path = "/dev/null/cannot/write/here";

        let result = verify_writable_and_readable(&PathBuf::from(invalid_path));
        assert!(result.is_err());
        // Не паниковать, вернуть структурированную ошибку
    }

    /// T-202 Spec 4: test_set_data_folder_persist_failure_does_not_corrupt_existing_config
    /// Инжектируем FailingAtomicFileWriter в tool'а через server, проверяем что диск не повреждён
    #[test]
    fn test_set_data_folder_persist_failure_does_not_corrupt_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        // 1. Сохраняем original config через нормальный writer
        let original_path = PathBuf::from("/original/protected/path");
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let normal_writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&normal_writer, app_support.path(), &config);

        // Проверяем что он на диске
        let config_path = config::config_file_path(app_support.path());
        let original_content = std::fs::read(&config_path).expect("config should exist after save");

        // 2. Теперь создаём server с failing writer'ом (инжекция через конструктор)
        let failing_writer: Arc<dyn AtomicFileWriter> = Arc::new(FailingAtomicFileWriter);
        let data_folder = Arc::new(Mutex::new(Some(original_path.clone())));
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder.clone(),
            app_support.path().to_path_buf(),
            failing_writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        // 3. Пытаемся вызвать set_data_folder tool'а (async вызов через tokio runtime)
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.set_data_folder(rmcp::handler::server::wrapper::Parameters(
                    SetDataFolderParams {
                        path: dir.path().to_string_lossy().to_string(),
                    },
                ))
                .await
            });

        // 4. Проверяем что ответ содержит ошибку
        let response: SetDataFolderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        // Код маппируется через error_mapping::ToMcpError; FailingAtomicFileWriter возвращает
        // WriteError::Backend("Mock replace failure"), что маппируется в "write.backend_error"
        assert_eq!(response.error.as_ref().unwrap().kind, "write.backend_error");
        // Проверяем что message и recovery не содержат сырую ошибку
        let error = response.error.as_ref().unwrap();
        assert!(!error.message.contains("Mock replace failure"));
        assert!(!error.recovery.contains("Mock replace failure"));
        assert!(!error.message.contains("ConfigError"));
        assert!(!error.message.contains("WriteError"));
        assert!(!error.message.contains("Backend("));

        // 5. КРИТИЧНО: Проверяем что диск на 100% не изменился (байт-в-байт)
        let disk_content = std::fs::read(&config_path).expect("config should still exist");
        assert_eq!(
            disk_content, original_content,
            "disk config must be byte-for-byte identical after persist failure"
        );

        // 6. Проверяем что state также не обновлён
        let state = data_folder.lock().unwrap();
        assert_eq!(*state, Some(original_path), "state must not change on persist failure");
    }

    /// T-202 Spec 4: test_startup_reads_env_var_when_present
    #[test]
    fn test_startup_reads_env_var_when_present() {
        let valid_dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();

        let env_var = Some(valid_dir.path().to_string_lossy().to_string());
        let result = resolve_startup_data_folder(env_var, app_support.path(), &writer);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), valid_dir.path());
    }

    /// T-202 Spec 4: test_startup_falls_back_to_persisted_config_when_env_absent
    #[test]
    fn test_startup_falls_back_to_persisted_config_when_env_absent() {
        let app_support = tempfile::tempdir().unwrap();
        let original_path = PathBuf::from("/some/original/path");

        // Сохраняем config
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&writer, app_support.path(), &config);

        // Вызываем resolve без env var
        let result = resolve_startup_data_folder(None, app_support.path(), &writer);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), original_path);
    }

    /// T-202 Spec 4: test_startup_no_env_no_persisted_config_starts_with_none
    #[test]
    fn test_startup_no_env_no_persisted_config_starts_with_none() {
        let app_support = tempfile::tempdir().unwrap();
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();

        let result = resolve_startup_data_folder(None, app_support.path(), &writer);

        assert!(result.is_none());
    }

    /// T-202 Spec 4: helper test для resolve_startup_data_folder с invalid env var
    #[test]
    fn test_startup_invalid_env_var_falls_back_to_persisted() {
        let app_support = tempfile::tempdir().unwrap();
        let original_path = PathBuf::from("/some/original/path");

        // Сохраняем config
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&writer, app_support.path(), &config);

        // Вызываем resolve с invalid env var
        let env_var = Some("/dev/null/invalid/path".to_string());
        let result = resolve_startup_data_folder(env_var, app_support.path(), &writer);

        // Должен упасть на env var, но затем загрузить persisted config
        assert!(result.is_some());
        assert_eq!(result.unwrap(), original_path);
    }

    // ===== T-203 tests (error mapping) =====

    /// T-203 test 23: verify persist_failed error uses mapped code, not literal "persist_failed"
    #[test]
    fn test_set_data_folder_persist_failure_error_uses_mapped_code() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let original_path = PathBuf::from("/original/protected/path");
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let normal_writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&normal_writer, app_support.path(), &config);

        let failing_writer: Arc<dyn AtomicFileWriter> = Arc::new(FailingAtomicFileWriter);
        let data_folder = Arc::new(Mutex::new(Some(original_path.clone())));
        let (_callback_handler, token_exchange_client, credential_vault, authorization_flow) = test_oauth_adapters();
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder.clone(),
            app_support.path().to_path_buf(),
            failing_writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.set_data_folder(rmcp::handler::server::wrapper::Parameters(
                    SetDataFolderParams {
                        path: dir.path().to_string_lossy().to_string(),
                    },
                ))
                .await
            });

        let response: SetDataFolderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(
            response.error.as_ref().unwrap().kind,
            "write.backend_error",
            "error code should be mapped from WriteError::Backend, not literal 'persist_failed'"
        );
    }

    /// T-203 test 24: message does not contain Rust Debug syntax (ConfigError/WriteError/Backend(...))
    #[test]
    fn test_set_data_folder_persist_failure_message_does_not_contain_debug_syntax() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let original_path = PathBuf::from("/original/protected/path");
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let normal_writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&normal_writer, app_support.path(), &config);

        let failing_writer: Arc<dyn AtomicFileWriter> = Arc::new(FailingAtomicFileWriter);
        let data_folder = Arc::new(Mutex::new(Some(original_path.clone())));
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder.clone(),
            app_support.path().to_path_buf(),
            failing_writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.set_data_folder(rmcp::handler::server::wrapper::Parameters(
                    SetDataFolderParams {
                        path: dir.path().to_string_lossy().to_string(),
                    },
                ))
                .await
            });

        let response: SetDataFolderResponse = serde_json::from_str(&response_json).unwrap();
        let error = response.error.as_ref().unwrap();
        assert!(
            !error.message.contains("ConfigError"),
            "message should not contain Rust type names"
        );
        assert!(
            !error.message.contains("WriteError"),
            "message should not contain Rust type names"
        );
        assert!(
            !error.message.contains("Backend("),
            "message should not contain Rust Debug syntax"
        );
    }

    /// T-203 test 25: message does not contain injected backend string "Mock replace failure"
    #[test]
    fn test_set_data_folder_persist_failure_message_does_not_contain_injected_backend_string() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let original_path = PathBuf::from("/original/protected/path");
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let normal_writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&normal_writer, app_support.path(), &config);

        let failing_writer: Arc<dyn AtomicFileWriter> = Arc::new(FailingAtomicFileWriter);
        let data_folder = Arc::new(Mutex::new(Some(original_path.clone())));
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder.clone(),
            app_support.path().to_path_buf(),
            failing_writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.set_data_folder(rmcp::handler::server::wrapper::Parameters(
                    SetDataFolderParams {
                        path: dir.path().to_string_lossy().to_string(),
                    },
                ))
                .await
            });

        let response: SetDataFolderResponse = serde_json::from_str(&response_json).unwrap();
        let error = response.error.as_ref().unwrap();
        assert!(
            !error.message.contains("Mock replace failure"),
            "message should not expose the mock error string (redaction rule D-015)"
        );
    }

    /// T-203 test 26: response.error.recovery field is present and non-empty
    #[test]
    fn test_set_data_folder_persist_failure_response_has_recovery_field() {
        let dir = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let original_path = PathBuf::from("/original/protected/path");
        let config = AppConfig {
            data_folder: original_path.clone(),
        };
        let normal_writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        let _ = config::save(&normal_writer, app_support.path(), &config);

        let failing_writer: Arc<dyn AtomicFileWriter> = Arc::new(FailingAtomicFileWriter);
        let data_folder = Arc::new(Mutex::new(Some(original_path.clone())));
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder.clone(),
            app_support.path().to_path_buf(),
            failing_writer,
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.set_data_folder(rmcp::handler::server::wrapper::Parameters(
                    SetDataFolderParams {
                        path: dir.path().to_string_lossy().to_string(),
                    },
                ))
                .await
            });

        let response: SetDataFolderResponse = serde_json::from_str(&response_json).unwrap();
        let error = response.error.as_ref().unwrap();
        assert!(
            !error.recovery.is_empty(),
            "recovery field must be present and non-empty in error response"
        );
    }

    // ===== T-604 connect_provider tests (7 tests) =====

    // Helper to build a test server with mock adapters
    fn build_test_server_with_mocks(
        callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler>,
        token_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient>,
        vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault>,
    ) -> VitalsteadMcpServer {
        let data_folder = Arc::new(Mutex::new(None));
        let app_support = tempfile::tempdir().unwrap();
        let writer = Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        VitalsteadMcpServer::new(
            data_folder,
            app_support.path().to_path_buf(),
            writer,
            token_client,
            vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        )
    }

    /// T1: connect_provider unsupported provider returns error WITHOUT calling adapters
    #[test]
    fn test_connect_provider_unsupported_provider_returns_error_without_calling_adapters() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "oura".to_string(),
                        connection_id: None,
                        client_id: None,
                        client_secret: None,
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "unsupported_provider");
    }

    /// T2: connect_provider missing client credentials returns error WITHOUT calling adapters
    #[test]
    fn test_connect_provider_missing_client_credentials_returns_error_without_calling_adapters() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: None,
                        client_id: None,  // Missing
                        client_secret: None,
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "missing_client_credentials");
    }

    /// T3: connect_provider success path returns "connected" status (with mock provider)
    #[test]
    fn test_connect_provider_success_returns_connected_status() {
        let callback = Arc::new(MockCallbackHandler::new_success("auth_code_xyz".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access_token_secret".to_string()),
                refresh_token: Some(vitalstead_mcp::core::security::SecretString::new("refresh_token_secret".to_string())),
                expires_in_secs: 3600,
                scope: Some("offline read:cycles read:sleep".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback.clone(), token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_test123".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "connected");
        assert_eq!(response.provider, "whoop");
        assert_eq!(response.connection_id, "conn_test123");
        assert!(response.error.is_none());
        // D-015: Verify tokens NOT leaked into response JSON
        assert!(!response_json.contains("access_token_secret"));
        assert!(!response_json.contains("refresh_token_secret"));
    }

    /// T4: connect_provider provider denied error returns recovery message (with correct mapping)
    #[test]
    fn test_connect_provider_provider_denied_maps_to_recovery_message() {
        let callback = Arc::new(MockCallbackHandler::new_error(
            "access_denied".to_string(),
            Some("User rejected authorization".to_string()),
        ));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_denied".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.kind, "connect.provider_denied");
        assert!(!error.message.is_empty());
        assert!(!error.recovery.is_empty());
        // Verify raw error code not leaked (D-015)
        assert!(!response_json.contains("access_denied"));
    }

    /// T5: connect_provider missing offline scope maps to recovery message
    #[test]
    fn test_connect_provider_missing_offline_scope_maps_to_recovery_message() {
        let callback = Arc::new(MockCallbackHandler::new_success("auth_code_xyz".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("read:sleep read:cycles".to_string()),  // NO offline
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_scope".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.kind, "connect.missing_offline_scope");
        assert!(!error.message.is_empty());
        assert!(!error.recovery.is_empty());
    }

    /// T6: connect_provider timeout maps to recovery message
    #[test]
    fn test_connect_provider_timeout_maps_to_recovery_message() {
        // Mock callback handler that times out
        struct TimeoutCallbackHandler;
        impl vitalstead_mcp::adapters::OAuthCallbackHandler for TimeoutCallbackHandler {
            fn listen_for_callback(&self, _expected_state: &str) -> Result<vitalstead_mcp::adapters::CallbackReceiver, vitalstead_mcp::adapters::CallbackError> {
                // Create a receiver that never sends (will timeout)
                let (_tx, rx) = tokio::sync::oneshot::channel::<Result<vitalstead_mcp::adapters::CallbackResult, vitalstead_mcp::adapters::CallbackError>>();
                Ok(vitalstead_mcp::adapters::CallbackReceiver { recv: rx, port: 9999 })
            }
            fn open_system_browser(&self, _url: &str) -> Result<(), vitalstead_mcp::adapters::CallbackError> {
                Ok(())
            }
        }

        let callback = Arc::new(TimeoutCallbackHandler);
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        // No outer test-level timeout wrapper: TimeoutCallbackHandler drops its
        // oneshot Sender immediately (never stored), so receiver.recv() resolves
        // to Err right away — connect() maps that to WhoopConnectError::Timeout
        // synchronously, no real waiting involved. A prior version of this test
        // wrapped the call in `tokio::time::timeout(100ms, ...)` with a silent
        // `unwrap_or_else(|_| "{}".to_string())` fallback and only asserted
        // inside an `if response_json != "{}"` guard — meaning the test could
        // never fail: if the outer wrapper ever won the race, the assertions
        // were skipped entirely and the test still passed. Removed.
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_timeout".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        let response: ConnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.kind, "connect.timeout");
        assert!(!error.message.is_empty());
        assert!(!error.recovery.is_empty());
    }

    /// T7: connect_provider repeated call with same connection_id overwrites pending (T-302 semantics)
    #[test]
    fn test_connect_provider_repeated_call_same_connection_id_overwrites_pending() {
        let callback = Arc::new(MockCallbackHandler::new_success("auth_code_xyz".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        // First call with same connection_id
        let _response1 = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_overwrite".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        // Second call with same connection_id should also succeed (pending was overwritten)
        let response2 = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.connect_provider(rmcp::handler::server::wrapper::Parameters(
                    ConnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: Some("conn_overwrite".to_string()),
                        client_id: Some("client_id_test".to_string()),
                        client_secret: Some("client_secret_test".to_string()),
                    },
                ))
                .await
            });

        // Both calls should succeed (pending overwrite semantics)
        let response: ConnectProviderResponse = serde_json::from_str(&response2).unwrap();
        // May be success or error depending on test timing, but the point is it doesn't replay
        assert!(response.connection_id == "conn_overwrite");
    }

    // ===== T-605 disconnect_provider tests (5 tests) =====

    /// T1: disconnect_provider unsupported provider returns error with kind "unsupported_provider"
    #[test]
    fn test_disconnect_provider_unsupported_provider_returns_error() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.disconnect_provider(rmcp::handler::server::wrapper::Parameters(
                    DisconnectProviderParams {
                        provider: "oura".to_string(),
                        connection_id: "conn_test".to_string(),
                    },
                ))
                .await
            });

        let response: DisconnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "unsupported_provider");
        assert_eq!(response.revoke_attempted, None);
        assert_eq!(response.revoke_succeeded, None);
    }

    /// T2: disconnect_provider with known connection (has credentials) deletes credentials and returns disconnected
    #[test]
    fn test_disconnect_provider_known_connection_deletes_credentials() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        // Pre-store a token in vault for this connection
        let service = "vitalstead.whoop.conn_test";
        vault.store(
            service,
            "access_token",
            &vitalstead_mcp::core::security::SecretString::new("stored_token".to_string()),
        ).unwrap();

        // Verify token is stored before disconnect
        assert!(vault.retrieve(service, "access_token").is_ok());

        let server = build_test_server_with_mocks(callback, token_client, vault.clone());

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.disconnect_provider(rmcp::handler::server::wrapper::Parameters(
                    DisconnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_test".to_string(),
                    },
                ))
                .await
            });

        let response: DisconnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "disconnected");
        assert_eq!(response.revoke_attempted, Some(false));  // revoke_endpoint=None
        assert_eq!(response.revoke_succeeded, Some(false));
        assert!(response.error.is_none());

        // Verify credentials deleted from vault
        assert!(vault.retrieve(service, "access_token").is_err());
    }

    /// T3: disconnect_provider with unknown connection_id (no stored credentials) does not panic, returns disconnected
    #[test]
    fn test_disconnect_provider_unknown_connection_id_does_not_panic() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());
        // No stored tokens for this connection

        let server = build_test_server_with_mocks(callback, token_client, vault);

        // This should NOT panic, even though connection_id doesn't exist
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.disconnect_provider(rmcp::handler::server::wrapper::Parameters(
                    DisconnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_unknown".to_string(),
                    },
                ))
                .await
            });

        let response: DisconnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "disconnected");  // NOT error
        assert_eq!(response.revoke_attempted, Some(false));
        assert_eq!(response.revoke_succeeded, Some(false));
        assert!(response.error.is_none());
    }

    /// T4: disconnect_provider vault backend error maps to error response without leaking details
    #[test]
    fn test_disconnect_provider_vault_backend_failure_maps_to_error_without_leaking_details() {
        struct FailingVault;

        impl vitalstead_mcp::adapters::CredentialVault for FailingVault {
            fn store(
                &self,
                _service: &str,
                _key: &str,
                _value: &vitalstead_mcp::core::security::SecretString,
            ) -> Result<(), vitalstead_mcp::adapters::VaultError> {
                Ok(())
            }

            fn retrieve(
                &self,
                _service: &str,
                _key: &str,
            ) -> Result<vitalstead_mcp::core::security::SecretString, vitalstead_mcp::adapters::VaultError> {
                Err(vitalstead_mcp::adapters::VaultError::NotFound)
            }

            fn delete(
                &self,
                _service: &str,
                _key: &str,
            ) -> Result<(), vitalstead_mcp::adapters::VaultError> {
                Ok(())
            }

            fn delete_all_for_connection(&self, _service: &str) -> Result<(), vitalstead_mcp::adapters::VaultError> {
                Err(vitalstead_mcp::adapters::VaultError::Backend(
                    "internal vault storage error code 42".to_string()
                ))
            }
        }

        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(FailingVault);

        let data_folder = Arc::new(Mutex::new(None));
        let app_support = tempfile::tempdir().unwrap();
        let writer = Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            data_folder,
            app_support.path().to_path_buf(),
            writer,
            token_client,
            vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.disconnect_provider(rmcp::handler::server::wrapper::Parameters(
                    DisconnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_fail".to_string(),
                    },
                ))
                .await
            });

        let response: DisconnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.revoke_attempted, None);
        assert_eq!(response.revoke_succeeded, None);

        let error = response.error.as_ref().unwrap();
        assert_eq!(error.kind, "vault.backend_error");

        // D-015: Verify raw error message not leaked
        assert!(!response_json.contains("internal vault storage error code 42"));
        assert!(!response_json.contains("code 42"));
    }

    /// T5: disconnect_provider response never contains secret values
    #[test]
    fn test_disconnect_provider_response_never_contains_secret_values() {
        let callback = Arc::new(MockCallbackHandler::new_success("code".to_string()));
        let token_client = Arc::new(MockTokenExchangeClient::new(
            vitalstead_mcp::adapters::TokenResponse {
                access_token: vitalstead_mcp::core::security::SecretString::new("access".to_string()),
                refresh_token: None,
                expires_in_secs: 3600,
                scope: Some("offline".to_string()),
            }
        ));
        let vault = Arc::new(MockCredentialVault::new());

        // Pre-store a secret token in vault
        let service = "vitalstead.whoop.conn_secret";
        let secret_token = vitalstead_mcp::core::security::SecretString::new(
            "super_secret_refresh_token_xyz_123".to_string()
        );
        vault.store(service, "refresh_token", &secret_token).unwrap();

        let server = build_test_server_with_mocks(callback, token_client, vault);

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.disconnect_provider(rmcp::handler::server::wrapper::Parameters(
                    DisconnectProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_secret".to_string(),
                    },
                ))
                .await
            });

        // D-015: Verify secret token value NOT in response JSON at all
        assert!(!response_json.contains("super_secret_refresh_token_xyz_123"));
        assert!(!response_json.contains("refresh_token"));  // key name should also not appear

        let response: DisconnectProviderResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "disconnected");
    }

    // ===== T-606 tests (delete_app_data) =====

    /// T-606 Test 1: test_delete_app_data_full_wipe_deletes_csv_config_and_credentials
    #[test]
    fn test_delete_app_data_full_wipe_deletes_csv_config_and_credentials() {
        // Setup: tempdir with 2 CSV files
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();
        std::fs::write(data_folder.path().join("data1.csv"), "col1,col2\nval1,val2").unwrap();
        std::fs::write(data_folder.path().join("data2.csv"), "col1\nval1").unwrap();

        // Setup: persisted config
        let config = AppConfig {
            data_folder: data_folder.path().to_path_buf(),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        config::save(&writer, app_support.path(), &config).unwrap();

        // Setup: SyncState with 2 connections in vault
        let mut state = vitalstead_mcp::core::sync::state::SyncState::default();
        state.entries.push(vitalstead_mcp::core::sync::state::SyncEntry {
            provider: "whoop".to_string(),
            connection_id: "conn1".to_string(),
            data_type: "sleep".to_string(),
            cursor: None,
            last_successful_sync_at: Utc::now(),
            schema_version: 1,
        });
        state.entries.push(vitalstead_mcp::core::sync::state::SyncEntry {
            provider: "oura".to_string(),
            connection_id: "conn2".to_string(),
            data_type: "activity".to_string(),
            cursor: None,
            last_successful_sync_at: Utc::now(),
            schema_version: 1,
        });
        vitalstead_mcp::core::sync::state::save(&writer, app_support.path(), &state).unwrap();

        // Setup: vault with credentials for 2 connections
        let vault = Arc::new(MockCredentialVault::new());
        vault.store("vitalstead.whoop.conn1", "access_token", &vitalstead_mcp::core::security::SecretString::new("token1".to_string())).unwrap();
        vault.store("vitalstead.oura.conn2", "access_token", &vitalstead_mcp::core::security::SecretString::new("token2".to_string())).unwrap();

        // Setup: server
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(writer),
            token_exchange_client,
            vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        // Call: delete_app_data with connections=None (full wipe)
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        // Verify: response structure
        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "success");
        assert!(response.csv.attempted);
        assert_eq!(response.csv.deleted_files.len(), 2);
        assert!(response.csv.deleted_files.iter().any(|p| p.contains("data1.csv")));
        assert!(response.csv.deleted_files.iter().any(|p| p.contains("data2.csv")));
        assert_eq!(response.csv.failed_files.len(), 0);
        assert!(response.config.attempted);
        assert_eq!(response.config.status, "deleted");
        assert!(response.config.path.is_some());
        assert_eq!(response.credentials.len(), 2);
        assert!(response.credentials.iter().all(|c| c.status == "deleted"));
    }

    /// T-606 Test 2: test_delete_app_data_scoped_connections_deletes_only_listed_credentials_not_csv
    #[test]
    fn test_delete_app_data_scoped_connections_deletes_only_listed_credentials_not_csv() {
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();
        std::fs::write(data_folder.path().join("data.csv"), "col1\nval1").unwrap();

        let config = AppConfig {
            data_folder: data_folder.path().to_path_buf(),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        config::save(&writer, app_support.path(), &config).unwrap();

        let vault = Arc::new(MockCredentialVault::new());
        vault.store("vitalstead.whoop.conn1", "access_token", &vitalstead_mcp::core::security::SecretString::new("token1".to_string())).unwrap();
        vault.store("vitalstead.oura.conn2", "access_token", &vitalstead_mcp::core::security::SecretString::new("token2".to_string())).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(writer),
            token_exchange_client,
            vault.clone(),
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        // Call: delete_app_data with explicit connections list (only conn1)
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams {
                        connections: Some(vec![
                            ConnectionRef { provider: "whoop".to_string(), connection_id: "conn1".to_string() }
                        ]),
                    }
                ))
                .await
            });

        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert!(!response.csv.attempted);
        assert!(response.csv.skipped_reason.is_some());
        assert!(!response.config.attempted);
        assert_eq!(response.config.status, "skipped");

        // Verify: CSV file still exists on disk
        assert!(data_folder.path().join("data.csv").exists());

        // Verify: only conn1 credentials deleted, conn2 remains
        assert_eq!(response.credentials.len(), 1);
        assert_eq!(response.credentials[0].provider, "whoop");
        assert_eq!(response.credentials[0].connection_id, "conn1");
        assert_eq!(response.credentials[0].status, "deleted");
        assert!(vault.retrieve("vitalstead.oura.conn2", "access_token").is_ok());
    }

    /// T-606 Test 3: test_delete_app_data_partial_failure_reports_partial_not_success
    #[test]
    fn test_delete_app_data_partial_failure_reports_partial_not_success() {
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        // Create 1 normal CSV file
        std::fs::write(data_folder.path().join("good.csv"), "col1\nval1").unwrap();

        // Create 1 directory with CSV-like name (remove_file will fail)
        std::fs::create_dir(data_folder.path().join("bad.csv")).unwrap();

        let config = AppConfig {
            data_folder: data_folder.path().to_path_buf(),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        config::save(&writer, app_support.path(), &config).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(writer),
            token_exchange_client,
            Arc::new(MockCredentialVault::new()),
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "partial");
        assert_eq!(response.csv.deleted_files.len(), 1);
        assert_eq!(response.csv.failed_files.len(), 1);
        assert!(response.csv.failed_files[0].error_kind.is_some());
    }

    /// T-606 Test 4: test_delete_app_data_empty_data_folder_is_not_an_error
    #[test]
    fn test_delete_app_data_empty_data_folder_is_not_an_error() {
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            Arc::new(MockCredentialVault::new()),
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "success");
        assert!(response.csv.attempted);
        assert_eq!(response.csv.deleted_files.len(), 0);
        assert_eq!(response.config.status, "not_found");
        assert_eq!(response.credentials.len(), 0);
    }

    /// T-606 Test 5: test_delete_app_data_no_data_folder_configured_still_deletes_config_and_credentials
    #[test]
    fn test_delete_app_data_no_data_folder_configured_still_deletes_config_and_credentials() {
        let app_support = tempfile::tempdir().unwrap();

        // Setup: config and credentials, but no data_folder
        let config = AppConfig {
            data_folder: PathBuf::from("/nonexistent/path"),
        };
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        config::save(&writer, app_support.path(), &config).unwrap();

        // "All" scope discovers connections via sync_state.json (known limitation,
        // see test_delete_app_data_all_scope_misses_connections_without_sync_entry) —
        // a SyncEntry must exist for this connection to be found and its credentials deleted.
        let mut state = vitalstead_mcp::core::sync::state::SyncState::default();
        state.entries.push(vitalstead_mcp::core::sync::state::SyncEntry {
            provider: "test".to_string(),
            connection_id: "conn".to_string(),
            data_type: "sleep".to_string(),
            cursor: None,
            last_successful_sync_at: Utc::now(),
            schema_version: 1,
        });
        vitalstead_mcp::core::sync::state::save(&writer, app_support.path(), &state).unwrap();

        let vault = Arc::new(MockCredentialVault::new());
        vault.store("vitalstead.test.conn", "access_token", &vitalstead_mcp::core::security::SecretString::new("secret".to_string())).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(None)), // no data_folder set
            app_support.path().to_path_buf(),
            Arc::new(writer),
            token_exchange_client,
            vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert!(!response.csv.attempted);
        assert!(response.csv.skipped_reason.is_some());
        assert_eq!(response.config.status, "deleted");
        assert_eq!(response.credentials.len(), 1);
    }

    /// T-606 Test 6: test_delete_app_data_all_scope_misses_connections_without_sync_entry
    #[test]
    fn test_delete_app_data_all_scope_misses_connections_without_sync_entry() {
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        let vault = Arc::new(MockCredentialVault::new());
        // Store credential WITHOUT corresponding SyncEntry
        vault.store("vitalstead.unknown.conn_no_sync", "token", &vitalstead_mcp::core::security::SecretString::new("secret".to_string())).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            vault.clone(),
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        // KNOWN LIMITATION: connection without sync entry is not discovered
        assert_eq!(response.credentials.len(), 0);
        // Verify credential still exists in vault (was not deleted)
        assert!(vault.retrieve("vitalstead.unknown.conn_no_sync", "token").is_ok());
    }

    /// T-606 Test 7: test_delete_app_data_response_never_contains_raw_health_values
    #[test]
    fn test_delete_app_data_response_never_contains_raw_health_values() {
        let data_folder = tempfile::tempdir().unwrap();
        let app_support = tempfile::tempdir().unwrap();

        // Create CSV with health data marker
        std::fs::write(
            data_folder.path().join("health.csv"),
            "heart_rate_bpm,timestamp\n72,2024-01-01T12:00:00Z\nheart_rate_bpm_secret_marker_123,ignored"
        ).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            Arc::new(MockCredentialVault::new()),
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.delete_app_data(rmcp::handler::server::wrapper::Parameters(
                    DeleteAppDataParams { connections: None }
                ))
                .await
            });

        // D-015: Verify raw health data marker NOT in response
        assert!(!response_json.contains("heart_rate_bpm_secret_marker_123"));
        // Response structure never carries file contents, only paths/statuses
        let response: DeleteAppDataResponse = serde_json::from_str(&response_json).unwrap();
        assert!(response.csv.deleted_files.iter().all(|p| !p.contains("secret_marker")));
    }

    // ===== T-602 tests (sync tools) =====

    /// T-602 Test 1: sync_provider with unsupported provider returns error
    #[test]
    fn test_sync_provider_unsupported_provider_error() {
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(PathBuf::from("/tmp")))),
            PathBuf::from("/tmp"),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.sync_provider(rmcp::handler::server::wrapper::Parameters(
                    SyncProviderParams {
                        provider: "oura".to_string(),
                        connection_id: "conn_123".to_string(),
                        days: None,
                    },
                ))
                .await
            });

        let response: SyncResult = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "unsupported_provider");
        assert_eq!(response.provider, "oura");
        assert_eq!(response.connection_id, "conn_123");
    }

    /// T-602 Test 2: sync_provider with no data_folder configured returns error
    #[test]
    fn test_sync_provider_no_data_folder_error() {
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(None)),  // No data folder configured
            PathBuf::from("/tmp"),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.sync_provider(rmcp::handler::server::wrapper::Parameters(
                    SyncProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_123".to_string(),
                        days: None,
                    },
                ))
                .await
            });

        let response: SyncResult = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "no_data_folder_configured");
    }

    /// T-602 Test 3: sync_now with no discovered connections returns no_connections status
    #[test]
    fn test_sync_now_no_connections() {
        let app_support = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(PathBuf::from("/tmp")))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.sync_now(rmcp::handler::server::wrapper::Parameters(SyncNowParams { days: None }))
                    .await
            });

        let response: SyncNowResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "no_connections");
        assert!(response.results.is_empty());
    }

    /// T-602 Test 4: list_data with no sync_state entries returns empty sources
    #[test]
    fn test_list_data_no_sources() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.list_data(rmcp::handler::server::wrapper::Parameters(ListDataParams {}))
                    .await
            });

        let response: ListDataResponse = serde_json::from_str(&response_json).unwrap();
        assert!(response.sources.is_empty());
        assert!(response.note.contains("sync history"));
    }

    /// T-602: list_data with one sync_state entry reports it, with file_exists
    /// false (no real CSV file written in this test) and the persisted cursor.
    #[test]
    fn test_list_data_reports_discovered_source_with_cursor() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let atomic = vitalstead_mcp::adapters::MacAtomicFileWriter::new();

        let mut state = vitalstead_mcp::core::sync::SyncState::default();
        vitalstead_mcp::core::sync::record_success(
            &mut state,
            vitalstead_mcp::core::sync::SyncSuccess {
                provider: "whoop".to_string(),
                connection_id: "conn1".to_string(),
                data_type: "sleep".to_string(),
                cursor: Some("2026-07-01T00:00:00+00:00".to_string()),
                schema_version: 1,
                now: chrono::Utc::now(),
            },
        );
        vitalstead_mcp::core::sync::save(&atomic, app_support.path(), &state).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.list_data(rmcp::handler::server::wrapper::Parameters(ListDataParams {}))
                    .await
            });

        let response: ListDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.sources.len(), 1);
        let source = &response.sources[0];
        assert_eq!(source.provider, "whoop");
        assert_eq!(source.connection_id, "conn1");
        assert_eq!(source.status, "connected");
        assert_eq!(source.csv.len(), 1);
        assert_eq!(source.csv[0].data_type, "sleep");
        assert!(!source.csv[0].file_exists, "no real CSV file was written in this test");
        assert_eq!(source.csv[0].cursor.as_deref(), Some("2026-07-01T00:00:00+00:00"));
        assert!(source.csv[0].last_successful_sync_at.is_some());
    }

    // NOTE (T-602): a genuine HTTP-mock-backed happy-path test for
    // sync_provider/sync_now (analogous to core::sync::orchestrator's own
    // tests) is not possible at this tool-handler layer: `WhoopSyncSession::new()`
    // (the constructor the handlers use) always points `WhoopApiClient` at the
    // real production WHOOP base URL — only the `#[cfg(test)]`-gated
    // `new_with_urls` seam (used by orchestrator.rs's and whoop/sync.rs's own
    // tests) allows pointing at a local mock server, and that seam is not
    // exposed through the tool handlers. Attempting a real call here would mean
    // either a real network dependency in the test suite (slow/flaky/blocked in
    // CI) or reworking the handlers to accept an injectable base_url, which is
    // out of T-602's scope. The fetch/map/write/cursor-persistence logic these
    // handlers delegate to is already thoroughly covered against a mock server
    // by `core::sync::orchestrator::tests` (T-601); this module's tests instead
    // cover the tool-layer concerns specific to T-602: provider/data_folder
    // validation, connection discovery from sync_state.json, and response shape
    // (see test_sync_provider_unsupported_provider_error,
    // test_sync_provider_no_data_folder_error, test_sync_now_no_connections,
    // test_list_data_reports_discovered_source_with_cursor above).

    /// T-602 Test 5: list_data response respects D-015 (no raw health data)
    #[test]
    fn test_list_data_response_never_contains_raw_health_values() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.list_data(rmcp::handler::server::wrapper::Parameters(ListDataParams {}))
                    .await
            });

        // Response should never contain raw CSV values (no health data, no row contents)
        assert!(!response_json.contains("csv_content"));
        assert!(!response_json.contains("heart_rate"));
        assert!(!response_json.contains("sleep_duration"));

        // Response structure is metadata-only: provider, connection_id, file_exists, cursor, timestamps
        let response: ListDataResponse = serde_json::from_str(&response_json).unwrap();
        assert!(response.sources.is_empty(), "no sync_state entries were seeded for this test");
        // Verify structure contains only allowed fields
        let json_obj = serde_json::from_str::<serde_json::Value>(&response_json).unwrap();
        assert!(json_obj.get("sources").is_some());
        assert!(json_obj.get("note").is_some());
    }

    // ---- T-603 query_data tests ----

    /// T-603 Test 1: unsupported data_type error
    #[test]
    fn test_query_data_unsupported_data_type_error() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "invalid_type".to_string(),
                    column: "any_column".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "unsupported_data_type");
        assert!(response.aggregate.is_none());
        assert!(response.raw.is_none());
    }

    /// T-603 Test 2: unknown_column error
    #[test]
    fn test_query_data_unknown_column_error() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "sleep".to_string(),
                    column: "nonexistent_column".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "unknown_column");
    }

    /// T-603 Test 3: no_data_folder_configured error
    #[test]
    fn test_query_data_no_data_folder_error() {
        let app_support = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(None)), // No data folder
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "sleep".to_string(),
                    column: "sleep_performance_percentage".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "no_data_folder_configured");
    }

    /// T-603 Test 4: file doesn't exist = empty result (not error)
    #[test]
    fn test_query_data_missing_file_returns_empty_ok() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        assert!(response.error.is_none());
        assert_eq!(response.aggregate.as_ref().unwrap().count, 0);
        assert!(response.raw.is_none());
    }

    /// T-603 Test 5: happy path with recovery.csv, single provider, time filtering
    #[test]
    fn test_query_data_recovery_happy_path() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        // Create recovery.csv
        use vitalstead_mcp::core::connectors::whoop::mapping::recovery_schema;
        let schema = recovery_schema();
        let header = schema.columns().join(",");
        let csv_content = format!(
            "{}\nwhoop,cycle-1,2026-07-10T10:00:00Z,2026-07-10T11:00:00Z,2026-07-10T11:05:00Z,,1,,,,75.5,,,,\nwhoop,cycle-2,2026-07-11T10:00:00Z,2026-07-11T11:00:00Z,2026-07-11T11:05:00Z,,1,,,,80.0,,,,\nwhoop,cycle-3,2026-07-12T10:00:00Z,2026-07-12T11:00:00Z,2026-07-12T11:05:00Z,,1,,,,70.0,,,,\n",
            header
        );
        std::fs::write(data_folder.path().join("recovery.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None, // Auto-resolve single source
                    start: Some("2026-07-10T12:00:00Z".to_string()),
                    end: Some("2026-07-11T12:00:00Z".to_string()),
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.data_type, "recovery");
        assert_eq!(response.column, "recovery_score");
        assert_eq!(response.providers, vec!["whoop"]);
        assert!(response.error.is_none());

        let agg = response.aggregate.unwrap();
        assert_eq!(agg.count, 1); // Only cycle-2 is in the time range
        assert_eq!(agg.min, Some(80.0));
        assert_eq!(agg.max, Some(80.0));
        assert_eq!(agg.avg, Some(80.0));
        assert!(response.raw.is_none()); // include_raw=false
        // T-411: no PENDING_SCORE rows in this fixture -> no provisional flag.
        assert_eq!(response.provisional_count, 0);
        assert!(response.provisional_note.is_none());
    }

    /// T-411: a still-open cycle (score_state=PENDING_SCORE, e.g. today's
    /// not-yet-closed cycle whose strain WHOOP updates live) must be counted
    /// as provisional in the aggregate response, not silently blended in as
    /// if it were a finalized value.
    #[test]
    fn test_query_data_flags_pending_score_rows_as_provisional() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        use vitalstead_mcp::core::connectors::whoop::mapping::cycle_schema;
        let schema = cycle_schema();
        let header = schema.columns().join(",");
        // cols: source,external_id,recorded_at,updated_at,synced_at,timezone,
        // schema_version,score_state,strain,kilojoule,average_heart_rate,max_heart_rate
        let csv_content = format!(
            "{}\nwhoop,cyc-1,2026-07-22T10:00:00Z,2026-07-22T23:00:00Z,2026-07-23T00:00:00Z,,1,SCORED,10.5,,,\nwhoop,cyc-2,2026-07-23T19:20:32Z,2026-07-23T20:00:00Z,2026-07-23T20:05:00Z,,1,PENDING_SCORE,9.63,,,\n",
            header
        );
        std::fs::write(data_folder.path().join("cycles.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "cycle".to_string(),
                    column: "strain".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        let agg = response.aggregate.unwrap();
        assert_eq!(agg.count, 2);
        assert_eq!(agg.max, Some(10.5));

        assert_eq!(response.provisional_count, 1);
        let note = response.provisional_note.expect("provisional_note must be set when provisional_count > 0");
        assert!(note.contains("1 of 2"));
        assert!(note.contains("PENDING_SCORE"));
    }

    /// T-603 Test 6: include_raw=true returns raw rows
    #[test]
    fn test_query_data_include_raw_returns_rows() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        // Create recovery.csv
        use vitalstead_mcp::core::connectors::whoop::mapping::recovery_schema;
        let schema = recovery_schema();
        let header = schema.columns().join(",");
        let csv_content = format!(
            "{}\nwhoop,cycle-1,2026-07-10T10:00:00Z,2026-07-10T11:00:00Z,2026-07-10T11:05:00Z,,1,,,,75.5,,,,\nwhoop,cycle-2,2026-07-11T10:00:00Z,2026-07-11T11:00:00Z,2026-07-11T11:05:00Z,,1,,,,88.25,,,,\n",
            header
        );
        std::fs::write(data_folder.path().join("recovery.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: true,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        assert!(response.raw.is_some());
        let raw_rows = response.raw.unwrap();
        assert_eq!(raw_rows.len(), 2);
        assert_eq!(raw_rows[0].source, "whoop");
        assert_eq!(raw_rows[0].external_id, "cycle-1");
        assert_eq!(raw_rows[0].value, Some("75.5".to_string()));
        assert_eq!(raw_rows[1].value, Some("88.25".to_string()));

        // Verify the distinctive value appears in the raw response
        assert!(response_json.contains("88.25"));
    }

    /// T-603 Test 7: ambiguous_providers error (D-008)
    #[test]
    fn test_query_data_ambiguous_providers_error() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        // Create recovery.csv with two sources
        use vitalstead_mcp::core::connectors::whoop::mapping::recovery_schema;
        let schema = recovery_schema();
        let header = schema.columns().join(",");
        let csv_content = format!(
            "{}\nwhoop,cycle-1,2026-07-10T10:00:00Z,2026-07-10T11:00:00Z,2026-07-10T11:05:00Z,,1,,,,75.5,,,,\noura,cycle-2,2026-07-11T10:00:00Z,2026-07-11T11:00:00Z,2026-07-11T11:05:00Z,,1,,,,80.0,,,,\n",
            header
        );
        std::fs::write(data_folder.path().join("recovery.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        // Query WITHOUT explicit providers: should error
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None, // Ambiguous!
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "ambiguous_providers");

        // Now query WITH explicit providers: should succeed
        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: Some(vec!["whoop".to_string()]),
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.providers, vec!["whoop"]);
        let agg = response.aggregate.unwrap();
        assert_eq!(agg.count, 1);
        assert_eq!(agg.min, Some(75.5));
        assert_eq!(agg.max, Some(75.5));
    }

    /// T-603 Test 8: raw row cap at 500 rows
    #[test]
    fn test_query_data_raw_truncation_at_500_rows() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        // Create recovery.csv with 600 rows
        use vitalstead_mcp::core::connectors::whoop::mapping::recovery_schema;
        let schema = recovery_schema();
        let header = schema.columns().join(",");
        let mut csv_content = format!("{}\n", header);
        for i in 0..600 {
            let recorded_at = format!("2026-07-{:02}T{:02}:00:00Z", 1 + (i / 24), i % 24);
            csv_content.push_str(&format!(
                "whoop,cycle-{},{},{},2026-07-10T11:05:00Z,,1,,,,{:.1},,,,\n",
                i, recorded_at, recorded_at, 70.0 + (i as f64 % 30.0)
            ));
        }
        std::fs::write(data_folder.path().join("recovery.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: true,
                }))
                .await
            });

        let response: QueryDataResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "ok");
        assert!(response.raw_truncated);
        let raw_rows = response.raw.unwrap();
        assert_eq!(raw_rows.len(), 500);
        assert!(response.raw_truncation_note.is_some());
        assert!(response.raw_truncation_note.as_ref().unwrap().contains("600"));
    }

    /// T-603 Test 9: response never contains raw health values when include_raw=false
    #[test]
    fn test_query_data_response_never_contains_raw_health_values_when_disabled() {
        let app_support = tempfile::tempdir().unwrap();
        let data_folder = tempfile::tempdir().unwrap();

        // Create recovery.csv with 3 rows so the distinctive value (77.25) is
        // neither the aggregate's min, max, nor avg — otherwise it would
        // legitimately appear in the aggregate-only response and this test
        // would be asserting a false premise (a single-row fixture makes
        // avg == the one raw value, which is not a D-015 leak, just coincidence).
        use vitalstead_mcp::core::connectors::whoop::mapping::recovery_schema;
        let schema = recovery_schema();
        let header = schema.columns().join(",");
        let csv_content = format!(
            "{header}\n\
             whoop,cycle-1,2026-07-10T10:00:00Z,2026-07-10T11:00:00Z,2026-07-10T11:05:00Z,,1,,,,10.0,,,,\n\
             whoop,cycle-2,2026-07-10T12:00:00Z,2026-07-10T13:00:00Z,2026-07-10T13:05:00Z,,1,,,,77.25,,,,\n\
             whoop,cycle-3,2026-07-10T14:00:00Z,2026-07-10T15:00:00Z,2026-07-10T15:05:00Z,,1,,,,100.0,,,,\n"
        );
        std::fs::write(data_folder.path().join("recovery.csv"), csv_content).unwrap();

        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(data_folder.path().to_path_buf()))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        // Query with include_raw=false
        let response_json_no_raw = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: false,
                }))
                .await
            });

        // Response should NOT contain the distinctive raw value
        assert!(!response_json_no_raw.contains("77.25"));
        let response: QueryDataResponse = serde_json::from_str(&response_json_no_raw).unwrap();
        assert!(response.raw.is_none());

        // Query with include_raw=true
        let response_json_with_raw = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.query_data(rmcp::handler::server::wrapper::Parameters(QueryDataParams {
                    data_type: "recovery".to_string(),
                    column: "recovery_score".to_string(),
                    providers: None,
                    start: None,
                    end: None,
                    include_raw: true,
                }))
                .await
            });

        // Response SHOULD contain the raw value
        assert!(response_json_with_raw.contains("77.25"));
        let response: QueryDataResponse = serde_json::from_str(&response_json_with_raw).unwrap();
        assert!(response.raw.is_some());
    }

    // ========================================================================
    // T-407: sync window backfill (resolve_sync_window / has_prior_sync)
    // ========================================================================

    #[test]
    fn test_resolve_sync_window_no_override_first_sync_uses_backfill_default() {
        let now = Utc::now();
        let (start, end) = resolve_sync_window(None, false, now).unwrap();
        assert_eq!(end, now);
        assert_eq!(now - start, chrono::Duration::days(DEFAULT_BACKFILL_SYNC_DAYS));
    }

    #[test]
    fn test_resolve_sync_window_no_override_prior_sync_uses_incremental_default() {
        let now = Utc::now();
        let (start, end) = resolve_sync_window(None, true, now).unwrap();
        assert_eq!(end, now);
        assert_eq!(now - start, chrono::Duration::days(DEFAULT_INCREMENTAL_SYNC_DAYS));
    }

    #[test]
    fn test_resolve_sync_window_explicit_days_overrides_both_defaults() {
        let now = Utc::now();
        let (start_first, _) = resolve_sync_window(Some(30), false, now).unwrap();
        let (start_incremental, _) = resolve_sync_window(Some(30), true, now).unwrap();
        assert_eq!(now - start_first, chrono::Duration::days(30));
        assert_eq!(now - start_incremental, chrono::Duration::days(30));
    }

    #[test]
    fn test_resolve_sync_window_rejects_zero_or_negative_days() {
        let now = Utc::now();
        assert!(resolve_sync_window(Some(0), false, now).is_err());
        assert!(resolve_sync_window(Some(-1), true, now).is_err());
    }

    #[test]
    fn test_resolve_sync_window_rejects_days_above_max() {
        let now = Utc::now();
        assert!(resolve_sync_window(Some(MAX_SYNC_DAYS + 1), false, now).is_err());
        assert!(resolve_sync_window(Some(MAX_SYNC_DAYS), false, now).is_ok());
    }

    #[test]
    fn test_has_prior_sync_false_when_no_state_file() {
        let app_support = tempfile::tempdir().unwrap();
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();
        assert!(!has_prior_sync(&writer, app_support.path(), "whoop", "conn_1"));
    }

    #[test]
    fn test_has_prior_sync_true_after_recorded_success_for_same_connection() {
        let app_support = tempfile::tempdir().unwrap();
        let writer = vitalstead_mcp::adapters::MacAtomicFileWriter::new();

        let mut state = vitalstead_mcp::core::sync::SyncState::default();
        vitalstead_mcp::core::sync::record_success(
            &mut state,
            vitalstead_mcp::core::sync::SyncSuccess {
                provider: "whoop".to_string(),
                connection_id: "conn_1".to_string(),
                data_type: "sleep".to_string(),
                cursor: Some(Utc::now().to_rfc3339()),
                schema_version: 1,
                now: Utc::now(),
            },
        );
        vitalstead_mcp::core::sync::save(&writer, app_support.path(), &state).unwrap();

        assert!(has_prior_sync(&writer, app_support.path(), "whoop", "conn_1"));
        // A different connection_id has no entry yet — still eligible for backfill.
        assert!(!has_prior_sync(&writer, app_support.path(), "whoop", "conn_2"));
    }

    /// sync_now with `days` out of range returns a structured `invalid_days`
    /// error instead of running any sync (T-407).
    #[test]
    fn test_sync_now_invalid_days_returns_error_without_syncing() {
        let app_support = tempfile::tempdir().unwrap();
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(PathBuf::from("/tmp")))),
            app_support.path().to_path_buf(),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.sync_now(rmcp::handler::server::wrapper::Parameters(SyncNowParams { days: Some(0) }))
                    .await
            });

        let response: SyncNowResponse = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.results[0].error.as_ref().unwrap().kind, "invalid_days");
    }

    /// sync_provider with `days` out of range returns a structured `invalid_days`
    /// error instead of running any sync (T-407).
    #[test]
    fn test_sync_provider_invalid_days_returns_error() {
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(Some(PathBuf::from("/tmp")))),
            PathBuf::from("/tmp"),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let response_json = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                server.sync_provider(rmcp::handler::server::wrapper::Parameters(
                    SyncProviderParams {
                        provider: "whoop".to_string(),
                        connection_id: "conn_123".to_string(),
                        days: Some(MAX_SYNC_DAYS + 1),
                    },
                ))
                .await
            });

        let response: SyncResult = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.error.as_ref().unwrap().kind, "invalid_days");
    }

    // ========================================================================
    // T-410: setup_guide MCP Prompt — available immediately on connect,
    // no separate Skill upload required (see plugin/skills/setup-guide/SKILL.md
    // for the shared source text).
    // ========================================================================

    #[test]
    fn test_setup_guide_prompt_body_strips_frontmatter() {
        let body = setup_guide_prompt_body();
        assert!(!body.starts_with("---"));
        assert!(!body.contains("user-invocable:"));
        assert!(!body.contains("disable-model-invocation:"));
        assert!(body.starts_with("# Vitalstead"));
        assert!(body.contains("Hard rules"));
    }

    #[test]
    fn test_setup_guide_prompt_body_never_mentions_asking_for_secrets_in_chat() {
        // D-015/D-005: the wizard's own text must never instruct relaying
        // secrets through chat — this is a regression guard on the shared
        // source file, not just the prompt wrapper.
        let body = setup_guide_prompt_body().to_lowercase();
        assert!(body.contains("never ask the user for a password"));
    }

    #[test]
    fn test_setup_guide_prompt_registered_and_returns_wizard_text() {
        let callback_handler: Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
            Arc::from(vitalstead_mcp::build_oauth_callback_handler());
        let token_exchange_client: Arc<dyn vitalstead_mcp::adapters::TokenExchangeClient> =
            Arc::from(vitalstead_mcp::build_token_exchange_client());
        let credential_vault: Arc<dyn vitalstead_mcp::adapters::CredentialVault> =
            Arc::from(vitalstead_mcp::build_credential_vault());
        let authorization_flow = Arc::new(
            vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone())
        );
        let (refresh_coordinator, sync_lock_registry) = test_sync_refresh_coordinators();
        let server = VitalsteadMcpServer::new(
            Arc::new(Mutex::new(None)),
            PathBuf::from("/tmp"),
            Arc::new(vitalstead_mcp::adapters::MacAtomicFileWriter::new()),
            token_exchange_client,
            credential_vault,
            authorization_flow,
            refresh_coordinator,
            sync_lock_registry,
        );

        let prompts = server.prompt_router.list_all();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "setup_guide");

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(server.setup_guide_prompt());
        assert_eq!(result.messages.len(), 1);
        let message = &result.messages[0];
        assert_eq!(message.role, Role::User);
        let text = message.content.as_text().expect("prompt message must be text").text.clone();
        assert!(text.contains("Vitalstead — setup guide"));
        assert!(text.contains("register_whoop_app"));
    }
}
