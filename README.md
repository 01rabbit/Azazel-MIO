# Azazel-MIO

**Azazelシリーズ共通のAI補助要員 — 状況を理解し、根拠を示し、次の一手を支える。**

## 名前と由来 — Mission Intelligence Operator

**M.I.O. は Mission Intelligence Operator の略称**です。読みは「ミオ」です。この名称は、Azazel-MIOの分離に伴って新しく作った略称ではなく、[Azazel-EdgeのM.I.O. Persona Profile](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/MIO_PERSONA_PROFILE.md)（[日本語版](https://github.com/01rabbit/Azazel-Edge/blob/main/docs/MIO_PERSONA_PROFILE_JA.md)、いずれも2026-10-27更新）で既に定義されていたものを引き継ぎます。

- **Mission（任務）**: 会話を目的化せず、現場の任務と安全な対応を支える。
- **Intelligence（情報・分析知見）**: 観測された事実、根拠、仮説、不明点を区別し、判断材料を整理する。
- **Operator（運用担当者）**: 人間の運用者に分かる形で説明・確認・引継ぎを支援する。M.I.O.自体が防御操作の実行権限を得るという意味ではない。

この3語の説明は、既存文書に記された正式名称と設計原則を読み解いたものです。**命名時の個人的な発想や語の選定過程が記録されているという主張ではありません。** 名称の初出・発案者・採用理由の一次記録は現時点で未確認です。

Edgeで「M.I.O.」と呼ばれてきたものには、オペレーター向けの**運用人格（persona）**と、制約付きの**認知・推論コア（cognitive core）**という異なる層があります。Azazel-MIOは後者を製品共通のPython助言コアとして所有します。前者の言葉遣い・利用者別案内・画面/チャネルへの適用は製品側で行い、人格を独立した実行主体や権限として扱いません。これは全てのEdgeの旧機能や画面がMIOに移管済みであることを意味しません。

正式名称の出典、Edgeからの責任分離、引き継ぐ振る舞いと製品側に残す機能、現時点の未移行事項は[名称・人格・機能の継承記録](docs/identity-and-origin.md)を参照してください。

M.I.O.は、Azazelの観測・知識・運用機能を使い、現場の担当者が状況を理解し、必要な通信を維持しながら対応し、専門家へ引き継ぐためのAI補助要員です。

Edgeでは現場の検知と通信状態を読み解き、Nexusではシステム全体の運用を支えます。動く場所や利用するモデルが変わっても、M.I.O.としての役割、根拠の扱い、安全上の境界は共通です。

> **現在の状態：基盤整備中。** このリポジトリには、ソースからインストールできる標準ライブラリのみのPython core（`azazel-mio`、Python 3.11+）があります。タグ付きの公開リリースや公開パッケージはまだありません。以下の役割分担は目標とする責任の整理で、製品への統合・移行が完了したことを意味しません。[製品別のAI inventory](docs/architecture/ai-inventory.md)は2026-11-04時点のスナップショットで、以後のmain更新を含まない場合があります。現在の統合状態を示すものとしてではなく、記録日時と対象SHAを確認して参照してください。現在のconsumer依存は[Edgeの依存宣言](https://github.com/01rabbit/Azazel-Edge/blob/main/requirements/runtime.txt)と[Nexusの任意依存宣言](https://github.com/01rabbit/Azazel-Nexus/blob/main/pyproject.toml)で確認してください。MIO mainの版とconsumerが固定した版は別管理であり、main更新だけで依存が更新されたことにはなりません。

ソースからの導入と最小の試験方法は [Common Python core](#common-python-core) を参照してください。

### 2026-11-07 の依存宣言と隔離受入候補

次の座標は別々に管理します。候補の受入は、mainへの統合、公開リリース、本番admissionや実機HGの完了を意味しません。上記inventoryの履歴値は維持します。

| 用途 | immutable MIO source / package version | 状態と確認先 |
| --- | --- | --- |
| Edge の現依存 | `a1807bf7abb08788b834ae038f7a8b46d09d0acc` / `0.1.0.dev20261106+gitbb6dcfd` | #47 系のpinを維持。[runtime依存宣言](https://github.com/01rabbit/Azazel-Edge/blob/15417868eb3bc3b441522e03142f79ccd9e59805/requirements/runtime.txt)を参照。 |
| Nexus 向け runtime 候補 | `989dd959a635b5877814bd2912639676308cf999` / `0.1.0.dev20261107+gited860f2` | 再現wheelとfocused試験を確認した候補。Nexus基準main `be653a95` の旧pinとは別で、main反映・全構成・cold installは別判定。 |
| IR 隔離候補 | #31 head `822865726c0eb8d834799f28fedce0a439cb0f45` / `0.1.0.dev20261107+git6899323.ir1` | 固定wheelをfresh venvへoffline installし、Debian ARM64 VMware guestで受入済み。runtimeとは別tuple・別venv。[PR #31](https://github.com/01rabbit/Azazel-MIO/pull/31)の候補とstandalone-vm手順を参照。MIO mainにIRが統合済みという意味ではない。 |

runtime/IRとも、受入manifestで指定されたimmutable wheelを用います。package versionやsource SHAだけでwheelの同一bytesを推定せず、配布時の受入manifestと照合してください。


## M.I.O.が目指すこと

専属のSOC担当者がいない現場でも、運用者が次の問いに答えられることを目指します。

- **何が起きているか。** 観測された事実と、AIの推測を分けて説明する。
- **どこまで分かっているか。** 根拠、矛盾、不足している情報、判断の限界を示す。
- **次に何を確認するか。** 通信への影響を考慮した、安全で具体的な確認手順を提案する。
- **何が実行されたか。** Edgeの判断、実際の適用結果、期限、解除状態を区別する。
- **どう復旧し、引き継ぐか。** 経緯と証拠を整理し、担当者や専門家が対応を継続できる形にする。

モデルが使えないときも、検証済みの参照情報と決定論的な案内へ縮退し、何が利用できないかを明示します。

## 一つのM.I.O.、複数の現場

以下は各場所での**目標とする役割**です。現在の製品実装は各製品リポジトリのREADMEを参照してください。[Azazel-Nexus](https://github.com/01rabbit/Azazel-Nexus)も公開リポジトリです。MIOは共通の助言コアを所有し、Nexusの導入・認可・起動監視の実装はNexus側で管理します。

| 利用する場所 | 目標とするM.I.O.の役割 |
| --- | --- |
| **Edge** | 検知の説明、NOC/SOCの状況整理、通信影響の確認、対処候補と次の観測の提案 |
| **Nexus** | 全体状況の要約、導入・運用の案内、障害復旧の支援、専門家への引継ぎ |
| **Knowledgeとの連携** | 出典・鮮度・信頼状態を伴う知識の参照、観測事実と知見の照合 |
| **Deceptionとの連携** | 仮説を確かめるための観測目的の提案、デコイで得られた反応の解釈 |

共通のM.I.O.であることは、単一のモデル、常時接続された中央サービス、全ノード間の記憶共有を前提としません。各環境で利用できる情報・資源・認可に応じて働き、見えていない情報を知っているようには扱いません。

## このリポジトリの責任

Azazel-MIOは、製品をまたいで共有するAI補助能力を所有します。

- 状況理解、仮説、矛盾、不足証拠の整理
- 根拠に結び付いた助言、説明、優先順位付け
- 範囲と予算を限定した、読取専用の情報要求
- Knowledgeを利用するための共通インターフェース
- モデルに依存しない推論処理とモデルアダプタの境界
- モデル不在・拒否・期限切れ時の案内と引継ぎ
- 共通の振る舞い、推論履歴、品質・安全性の評価

製品固有の観測、権限管理、実行、サービス運用は、それぞれの製品が担当します。

| リポジトリ | 主な責任 |
| --- | --- |
| [Azazel-MIO](https://github.com/01rabbit/Azazel-MIO) | 共通の状況理解・推論・助言・説明・評価 |
| [Azazel-Edge](https://github.com/01rabbit/Azazel-Edge) | 現場の観測、決定論的な防御判断、通信制御、期限と解除 |
| [Azazel-Nexus](https://github.com/01rabbit/Azazel-Nexus) | 導入、認可、資源管理、起動・監視、全体運用と表示 |
| [Azazel-Knowledge](https://github.com/01rabbit/Azazel-Knowledge) | 知識の収集・検証・保存・検索・配信 |
| [Azazel-Deception](https://github.com/01rabbit/Azazel-Deception) | 承認されたデコイ環境の隔離・実行・観測 |
| [Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric) | 製品間で受け渡す共通データ契約 |

共有する通信契約をM.I.O.独自の互換形式として複製せず、Fabricとの責任分担を明確にします。製品間のwire契約はFabricが所有します。一方、現在のM.I.O.内部API（[internal API v1](docs/api-v1.md)）と内部frame `mio.situation_frame.v2`（[`src/azazel_mio/contracts.py`](src/azazel_mio/contracts.py)で定義）はM.I.O.が所有します。この内部frameはFabricのwire契約ではなく、Fabric契約への対応付けも未完了です。モデルやruntimeの導入・認可・起動は、利用先の製品が管理します。

## 助言と実行の境界

**M.I.O.は助言を行います。防御行動の決定と執行はEdgeの決定論的な安全機構が担います。**

M.I.O.は、通信制御、デコイの起動・露出、権限変更を直接実行しません。提案は認可ではなく、AIの回答、Knowledgeの情報、外部の観測に実行権限を持たせません。

- 観測事実、外部知識、AIの推測、Edgeの判断、実行結果を分ける。
- 出典の欠落、情報の古さ、観測不能を正常や成功として表示しない。
- ログ・知識・デコイの反応に含まれる文章を、システムへの命令として扱わない。
- M.I.O.やモデルの停止・遅延が、Edgeの決定論的な防御経路を妨げないようにする。
- 外部モデルへの送信は、明示的な許可、情報分類、送信先認可、最小化を前提とする。
- ラボでの成功を、本番の認可、実機性能、安全性の証明へ読み替えない。

現行coreにはKnowledge LiteとContext responseを渡す型付きのin-process入力があります。どちらも`reported_unverified`の助言receiptで、出典が報告する内容を検証済み事実へ昇格させません。これらはKnowledgeへのnetwork接続ではありません。通信・認証・TLSは製品adapterの責務で、MIOには未実装です。詳細は[API境界](docs/api-v1.md)を参照してください。

## 最初に通す経路

最初の目標は、コードを移すことだけではありません。実際の出来事に対して、運用者が使える一連の補助を成立させます。

```text
観測・インシデント
  → 状況と根拠を整理
  → Knowledgeを参照
  → 仮説・不明点・次の安全な確認を提示
  → 担当者の確認結果やEdgeの実行結果を読み取る
  → 説明と引継ぎを更新
```

この流れを、まずモデルなしでも破綻しない形でつなぎ、認可されたモデルによる補助を段階的に追加します。

### 初期ロードマップ

1. **責任と契約を固定する。** 入出力、所有範囲、安全境界、利用先アダプタを定義する。
2. **既存資産を集約する。** Edgeの推論コア・評価ツールなどを、履歴と検証を保って段階的に移行する。
3. **製品から呼び出せる形にする。** EdgeとNexusが共通コアを利用し、各製品の権限境界と障害分離を維持する。
4. **Knowledgeの実連携を通す。** Liteと本体を区別し、実サービス同士で出典・期限・拒否・縮退を確認する。
5. **運用者の経路を検証する。** 表示、追加確認、結果の読戻し、復旧、引継ぎまでを通して評価する。

既存製品にある実装を、このREADMEだけで移行済みとは扱いません。現在のM.I.O.coreには、Edgeの推論コアの一部を移植したものが含まれています（[migration](docs/migration.md)）。Edgeには従来のモデル経路が残っており、共通coreの存在はすべてのAI支援が移行済みであることを意味しません。移行元と移行先の対応、互換性、試験結果を変更ごとに記録します。

## 完成をどう判断するか

返答が生成できることに加え、次を確認します。

- 重要な説明を観測や出典へたどれる。
- 不確実な状況で代替仮説を保ち、確認に役立つ案内を出せる。
- Knowledge・モデル・観測元が失われても、限界を明示して縮退できる。
- 古い結果、別インシデントの結果、撤回済みの要求を混同しない。
- モデルの出力や不正な入力が、実行権限の獲得につながらない。
- 応答時間と資源使用量が、対象環境の実測に基づく予算内に収まる。
- 非専門家・臨時SOC担当者が、説明を読み、次の操作と引継ぎへ進める。

単体試験、実サービス連携、VM、実機の結果は分けて記録します。文章の流暢さや試験件数だけで、補助要員としての完成を宣言しません。

## 開発への参加

現時点では、タグ付きの公開リリースや公開パッケージはありません。ソースからのインストールと試験の手順は末尾の「Common Python core」を参照してください。初期変更では、役割・契約・移行計画と、最小の実働経路を優先します。

IssueやPull Requestには、目的、対象製品、入力と出力、権限への影響、失敗時の動作、検証結果、未確認事項を記載してください。秘密情報、生の機密データ、内部識別情報、認証情報を例やログに含めないでください。

## Common Python core

`azazel-mio` は、標準ライブラリのみを使う助言専用のPython 3.11+パッケージです（`pyproject.toml` で実行時依存は宣言されていません）。製品がtransport・governance・永続化・決定論的執行を所有します。

**インストール（このチェックアウトから）**

```sh
python3 -m pip install .
```

開発時は編集可能インストールも使えます: `python3 -m pip install -e .`（`pyproject.toml` のsetuptools構成による。このREADMEの作成では実行していません）。

ビルド分離が有効なインストールでは、build-system要件の `setuptools>=77.0.3` が必要です。オフライン環境では、同要件を満たすwheelを事前に用意してください。インストール手順はこのREADMEの更新時点で実行確認していません。

現在のバージョンは `pyproject.toml` の `version` が正本です。その末尾のローカルサフィックスはソースの基準ラベルで、このコミットのSHAではありません。公開リリースではありません（[versioning](docs/versioning.md)）。

**試験**

`pyproject.toml` は試験ランナーを宣言していません。一部のテストは `import pytest` を使うため、`pytest` を別途導入して実行します（このREADMEの作成では実行していません）。`docs/assessment-baseline.md` の限定的なunittest baseline手順は Python 3.12+ を要求します。これはpytestを使う全テストの代替ではありません。一方、パッケージは Python 3.11+ を要求しますが、3.11での全試験実行は確認していません。

```sh
python3 -m pip install pytest
PYTHONPATH=src python3 -m pytest -q
```

**参照文書**

- 内部API: [internal API v1](docs/api-v1.md)
- セッション特徴からの助言専用仮説とオフライン評価（未校正・製品未接続）: [session behavior](docs/session-behavior.md)
- 決定論の案内（モデル無し）: `azazel_mio.guidance.build_guidance` は供給された報告と選択済み playbook から、報告の記述（未検証）・競合する説明・不明点（出典付き）・read-only の次確認・OBSERVE 固定の案内を組み立てます。`content_kind="deterministic_guidance"`、`model_calls=0`、`guidance_schema_version="1.0.0"`。版と互換性は [internal API v1](docs/api-v1.md) の guidance 節と Playbook versions 節を参照（auth-ambiguity-v1 は 1.2.0、dns-resolution-degradation-v1 は 1.0.0。保存済み receipt は再検証されず、prompt template 版は不変）。
- IR evidence import recovery: [IR evidence import recovery](docs/ir-import-recovery.md)
- 移行元と互換性: [source/license migration](docs/migration.md)
- バージョン: [versioning](docs/versioning.md)

**任意・評価用の機能（既定の試験には含まれません）**

- 実モデル確認: POSIX環境と、ローカルOllamaに導入済みのモデルが必要です。`PYTHONPATH=src python3 tools/real_model_smoke.py --model <local-tag>`。スクリプトの接続先はloopback（`127.0.0.1`）固定です。成功には、合成の助言フレームについて固定された3種類のモデルタスクを順番に各1回完了する必要があります。指定tagが未導入なら失敗終了します。モデル実行の後、同じコマンド内で同じフレームをモデルなしで実行し、決定論的フォールバックと`MODEL_NOT_AVAILABLE`を確認します。製品への採用、性能、真実性、本番の認可は証明しません（[real-model smoke](docs/real-model-smoke.md)）。
- オフラインplaybook ranking: 評価マイルストーンです。モデルの有効化、自動学習、認可、実行は含みません（[offline ranking](docs/offline-playbook-ranking.md)）。
- Assessment baseline: experimentalです（[assessment baseline](docs/assessment-baseline.md)）。
