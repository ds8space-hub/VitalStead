# Название продукта — анализ и решение

Статус: **принято**. Продукт переименован в **Vitalstead** — см. D-020 в
`docs/decisions.md` (решение и полный каскад по файлам). Этот документ —
исходный анализ, на основании которого было принято решение.

Дата анализа: 2026-07-16. Проверка коллизий — веб-поиск на эту дату;
перед финальным выбором перепроверить (магазины приложений, домены, trademark).

## Критерии (из анализа проекта)

Продукт по сути один тезис: *показатели здоровья пользователя живут файлами
на его земле* — local-first (D-001), CSV вместо базы (D-002), секреты не видит
даже модель (D-015), отключение не удаляет данные (D-010).

Аудитория MVP — технические privacy-пользователи Claude Desktop с wearable,
то есть публика, идентифицирующая себя с self-hosted / local-first этосом.

Требования к имени:

1. Несёт идею **владения**, а не «синхронизации» — sync-имена это commodity
   (в нише уже живёт FitnessSyncer).
2. Не привязано к MCP/Claude — Tauri-фасад родительского проекта разделит
   бренд позже (D-014).
3. Английское (D-012), однозначно пишется и произносится.
4. Без коллизий с существующими продуктами в health/wearable/self-hosted нишах.

Текущее «Control Your Data» — честный манифест, но как бренд слабое:
три слова, звучит как кнопка в GDPR-баннере, не гуглится и не присваивается.

## Рекомендация: Vitalstead

**vital** (жизненные показатели) + **-stead** (как в homestead/farmstead —
усадьба, свой надел). Читается как «усадьба для ваших витальных данных»;
метафора самодостаточного хозяйства попадает в идентичность local-first аудитории.

- Тэглайн: *"A homestead for your health data."*
- Для листинга в директории: *"Vitalstead — sync your wearables into local
  CSV files you own."*
- Бинарь/CLI: `vitalstead` — без дефисов.
- Зонтик: «Control Your Data» остаётся принципом/автором
  (`author.name` в обоих манифестах уже такой) — «Vitalstead by Control Your Data».

Проверка коллизий: на vitalstead.com — мелкий магазин с бойлерплейтом
shipping-protection; устоявшегося бренда/продукта нет, health/software-пространство
чистое. `.app` / `.health` / `.dev`, скорее всего, свободны (не проверялось).

Вариант того же приёма буквальнее: **Healthstead** (на коллизии не проверялся).

## Альтернативы

### Hearthbeat

**hearth** (домашний очаг) + **heartbeat**: «твой пульс — у домашнего очага».
Самая сильная словесная находка; продукта с таким именем не существует.

Риски: поиск автоматически исправляет в "Heartbeat" (сериалы, кардиосервис
Heartbeat Health) — SEO будет вечной борьбой с автокорректом; на слух
неотличимо от heartbeat; путаница с другим проектом владельца
(Azlo HeartHealth). Вариант для смелых.

### LocalVitals

Не бренд, а паттерн «описательное имя + подпись»: мгновенно понятен
в директории плагинов, ноль загадки, но и присвоить нельзя (описательные
имена в этой нише не защищаются; на коллизии не проверялся). Годится как
временное имя закрытого MVP, если брендинг откладывается.

### Krov (дикая карта)

По-русски одновременно «кров» и почти «кровь» — идеальный каламбур только
для русскоязычных; англоязычной аудитории не читается.

## Проверено и занято (не брать)

| Имя | Кем занято |
|---|---|
| Vitalog | Действующее healthcare-приложение (медкарты, приёмы) в App Store / Google Play |
| Vitalkeep | Испанский продукт мониторинга пожилых: браслет + IoT — прямая коллизия в wearable-нише |
| VitalVault | EMR-система (vitalvault.app) + сервис биомаркеров (vitalsvault.com) |
| Uncloud | Два живых проекта в той же self-hosted аудитории: uncloud.run (Docker-оркестрация), uncloud.gg (local-first инструмент) |
| Homebody | Множество фитнес-приложений и брендов; homebody.com занят |

## Механика переименования

Имя прошито в пяти местах:

1. `plugin/.claude-plugin/plugin.json` — `name: "vitalstead"`;
2. `mcpb/manifest.json` — `name`, `display_name`, `entry_point`/`command`
   (`server/vitalstead-mcp`);
3. `Cargo.toml` — package `vitalstead-mcp`, lib `vitalstead_mcp`,
   bin `vitalstead-mcp`;
4. префикс env-переменных `CYD_*` (`VITALSTEAD_OAUTH_FIXED_PORT`, `VITALSTEAD_DATA_FOLDER`) —
   упомянут в D-019, `plugin/.mcp.json`, `mcpb/manifest.json`, коде platform-слоя;
5. README и доки (`docs/*.md`).

Момент удачный: ручная проверка на чистой машине (EPIC-07) не проведена,
тестеры плагин не ставили — переименование ещё дёшево. После M6 (закрытый MVP
у тестеров) стоимость растёт: смена `name` плагина/бандла ломает обновление
по месту.

## Источники проверки коллизий

- [Vitalog (App Store)](https://apps.apple.com/us/app/vitalog/id6502337743)
- [VitalKeep](https://vitalkeep.com/en/home/)
- [VitalVault](https://vitalvault.app/)
- [Vitals Vault](https://www.vitalsvault.com/)
- [uncloud.run](https://uncloud.run/)
- [uncloud.gg](https://www.uncloud.gg/)
- [homebody.com](https://www.homebody.com/install)
- [Heartbeat Health](https://www.heartbeathealth.com/)
- [vitalstead.com](https://vitalstead.com/)
- [FitnessSyncer](https://www.fitnesssyncer.com/)
