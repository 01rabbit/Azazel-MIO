# M.I.O. 名称・人格・機能の継承記録

## 正式名称と出典

**M.I.O. = Mission Intelligence Operator**（読み: ミオ）。

この名称はAzazel-MIOリポジトリで新規に命名したものではない。Azazel-Edgeの以下の既存ドキュメントに明記されている。

- [M.I.O. Persona Profile (EN)](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/MIO_PERSONA_PROFILE.md): Definitionに `M.I.O. (Mission Intelligence Operator)` と記載。文書上の最終更新日 2026-10-27。
- [M.I.O. Persona Profile (JA)](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/MIO_PERSONA_PROFILE_JA.md): 定義に `M.I.O. は Mission Intelligence Operator の略称` と記載。同日更新。
- [M.I.O. Cognitive Plane](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/architecture/mio-cognitive-plane.md): 「Two things are called M.I.O.」として人格と認知コアの二層を区別。同日更新。

3語は次の役割を表すものと解釈する。

| 語 | 意図する役割 |
| --- | --- |
| Mission | 任務達成を優先し、会話の娯楽性より現場の安全・継続を重視する |
| Intelligence | 観測と外部知識、推測、不明点、根拠、信頼状態を分ける |
| Operator | 人間の運用者の理解・確認・引継ぎを助ける。AIに運用権限を与える意味ではない |

この表は既存の正式名称と設計原則の説明であり、命名当時の発案者・初出日時・個人的着想を裏付ける記録ではない。これらは未確認であり推測で埋めない。「Mission Intelligence Officer」等の別の展開形に置き換えない。

## 分離前の二つの「M.I.O.」

Edgeの[Cognitive Plane](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/architecture/mio-cognitive-plane.md)は、同じ名称で呼ぶ二層を明示している。

| 層 | Edge側の元の意味 | 独立したAzazel-MIOとの関係 |
| --- | --- | --- |
| **Operator persona** | ダッシュボード、`ops-comm`、Mattermost、トリアージなどで使うオペレーター向けの語り口と案内 | 伝えるべき原則と振る舞いを共有するが、各画面、チャンネル、ルーティング、文体適用、運用権限は製品側の責務 |
| **Cognitive core** | `SituationFrame`、playbook、仮説、証拠ギャップ、read-only照会、検証、縮退、履歴等の制約付き助言能力 | 製品中立の共通PythonコアとしてAzazel-MIOが所有する目標。Edge旧実装との移行は機能単位で検証する |

Edge側の文書は2026-10-27時点の構成を記録した**履歴的な出典**であり、現在のEdge実装全体がオフラインのみだという断定には使用しない。現時点で実際に利用される経路は[Edge README](https://github.com/01rabbit/Azazel-Edge/blob/main/README.md)、[MIO README](../README.md)、[migration](migration.md)と各製品の依存宣言・試験結果で確認する。

## Personaから継承する設計原則

1. **Deterministic first**: Edgeの決定論的な防御判断・適用をM.I.O.が上書きしない。人格の表現は権限ではない。
2. **Mission oriented**: 状況の理解、次に必要な確認、復旧、引継ぎを優先する。娯楽としての会話や不必要な擬人化を目的にしない。
3. **Audience aware**: 専門家向けには判断根拠、代替仮説、runbook・review状態、引継ぎを重視する。臨時担当者・初心者には短く安全な手順、禁止事項、引継ぎ先を優先する。
4. **Evidence before confidence**: 観測事実と推測、実行結果と助言を区別する。根拠不足・期限切れ・矛盾を隠さない。
5. **Bounded assistance**: 実行・権限変更・通信制御・デコイ起動を提案だけで許可しない。高い不確実性や権限不足では安全な確認と人間への引継ぎを優先する。
6. **Consistent communication**: 冷静、明瞭、簡潔、敬意を保ち、根拠のない安心断定を避ける。日本語・英語で用語の意味と安全境界を揃える。

上記は**目標と継承原則**であり、共通ライブラリが日本語/英語の全画面生成やユーザー種別切替を現時点で実装したという主張ではない。Edgeの日本語版Persona Profileにある「初心者は最大3手順」「見出しは英語固定」等の画面・利用者向け規則はEdge側の仕様であり、共通コアの全クライアントに機械的に課す契約ではない。適用する製品アダプタが、別途そのUI契約を定めて検証する。

## 責任と権限の境界

| 主体 | 所有すること | M.I.O.が代行しないこと |
| --- | --- | --- |
| MIO共通コア | 根拠付き状況理解、仮説、未知、説明、助言、読取専用要求の形、評価と縮退 | 生の観測収集、製品認可、プロセス管理、実行 |
| Edge | 観測、決定論的な防御決定、実際の適用、期限切れ解除、実績監査 | MIOの推奨を自動的に実行許可にすること |
| Nexus | インストール、モデル・サービス選択と認可、監視、オペレーター導線 | Edgeの防御決定の置換 |
| Knowledge | 出典・鮮度・信頼状態のある知識の収集、検証、保存、配信 | 防御行動の認可 |
| Fabric | 製品間wire契約と互換性 | MIO内部推論APIや防御決定 |
| Deception | 承認されたデコイ環境の隔離・起動・観測・終了 | AI仮説だけに基づく起動・露出 |

基本的な流れは **製品側の観測と認可 → MIOの制約付き助言 → 人間または製品側の決定論的な認可済み経路** である。MIOの出力、外部知識、モデルの文章は、実行許可や観測済み事実に自動昇格させない。モデル・Knowledge・transportが使えない時もEdgeの決定論的な防御経路は独立して継続する。

詳細は[ownership ADR](architecture/ownership-adr.md)と[internal API](api-v1.md)を参照。

## 実装と移行の状態を混同しない

- Azazel-MIOは現在、製品共通の助言専用Pythonライブラリを提供する。人格そのものが独立したサービスとして稼働するわけではない。
- Edgeの既存Persona Profileは文体や現場ワークフローの**原典**である。移行後の所有権がMIOに移ったこと、Mattermost・Dashboard・`ops-comm`がMIOの実装物になったことを意味しない。
- Edgeの従来のmodel/triage/routerやcognitive shadow経路を一括移行済みとしない。各製品は独立した依存pin、起動経路、権限分離、統合試験を持つ。
- MIOの内部SituationFrameとFabricの共有wire契約は別であり、同一形式とみなさない。
- ソフトウェア単体試験、model smoke、VM受入、製品結合、実機HIL、本番admissionを混同しない。現状は[README](../README.md)のstatus、[inventory](architecture/ai-inventory.md)、[migration](migration.md)で追跡する。

## この記録を更新するときの確認項目

- 略称を変更しない。変える場合は正式な命名決定とEdge・Azazel系列の整合を先に取る。
- 人格（説明の仕方）と共通の認知機能（何を計算するか）、そして製品側の実装（どこでどう使うか）を分ける。
- Edgeで実装済みのPersona固有機能を、未検証のままMIOライブラリの機能と書かない。
- 製品の権限と移行状態を正確な出典・revision・受入記録で裏付ける。
- 依存、公開リリース、モデル有効化、実機認可などに触れる場合は最新のソースと証拠を別途検証する。
