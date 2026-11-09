# gp-seac-access-rule-applet

Android向けのARA-M / ARA-D Java Cardアプレットです。アプリの署名証明書のSHA-1（20バイト）またはSHA-256（32バイト）ハッシュを登録し、その証明書で署名されたアプリにアクセス権限を付与します。

ARA-MとARA-Dはそれぞれ独立したCAPとしてビルドします。保存領域も独立しているため、同じルールを両方に適用する場合は、それぞれに登録してください。

## 対応範囲

| 種別 | パッケージAID | アプレットAID | 登録ハッシュに対するルール |
| --- | --- | --- | --- |
| ARA-M | `A00000015141434C` | `A00000015141434C00` | Carrier Privileges用の`4F06FFFFFFFFFFFF` + `DB080000000000000001`と、全SEアプリ対象の`4F00` + `D00101` |
| ARA-D | `A000000151444143` | `A00000015144414300` | Device API用の`DB080000000100010001` |

- 各インスタンスに最大16エントリ。SHA-1、SHA-256、全許可エントリ（`C100`）を混在できます。同じハッシュや全許可エントリの重複は拒否します。
- インストールパラメータを省略すると空の許可リストになります。
- スロット番号は`0..15`です。削除しても他のスロット番号は変わりません。
- ハッシュ一覧、アクセスルール、Refresh Tagは認証なしで読み出せます。
- 追加・変更・削除には、関連するSecurity DomainのSCP03認証と、コマンドごとのC-MAC検証が必要です。C-MACおよびC-MAC+C-ENCに対応します。
- SCP02、未認証の変更、認証後に送る平文の変更コマンドは拒否します。鍵管理と暗号処理にはカードOSの`GPSystem.getSecureChannel()`を使用します。
- ハッシュと8バイトのRefresh Tagを1トランザクションで更新します。同一ハッシュへの置換と失敗した操作ではRefresh Tagを変更しません。

対象カードにはJava Card 3.0.4 / 3.0.5 / 3.1.0の対応APIとGlobalPlatform Java API 1.6が必要です。

ARA-CやARFからの集約、パッケージ名・対象AID・権限マスクの個別設定、NFCイベントルール、GP標準のSTORE DATA管理TLV、R-MAC/R-ENC、Extended APDU、コマンドチェイニングには対応していません。管理APDUはこの実装独自のものです。

端末側のCarrier Privileges / OMAPI適用とキャッシュ更新は端末・OSの実装に依存します。導入先のカードとAndroid端末で、必要なアクセスだけが許可されることを確認してください。

## ビルド

AntとJDK 11を使用します。古いJava Card SDKをJDK 17以降で直接ビルドしないでください。

```sh
git submodule update --init --recursive
JAVA_HOME=/path/to/jdk-11 ant build_all
```

次の6種類のCAPと対応するJARを`out/`に生成します。`LICENSE`、`NOTICE`、`THIRD_PARTY_NOTICES.md`も同じディレクトリへコピーします。

| Java Card | ARA-M | ARA-D |
| --- | --- | --- |
| 3.0.4 | `ara_m_jc304.cap` | `ara_d_jc304.cap` |
| 3.0.5u4 | `ara_m_jc305.cap` | `ara_d_jc305.cap` |
| 3.1.0 | `ara_m_jc310.cap` | `ara_d_jc310.cap` |

対象を絞る場合は`ant build_jc304` / `ant build_jc305` / `ant build_jc310`を使用します。単体ビルドでは次のように指定します。

```sh
JAVA_HOME=/path/to/jdk-11 ant -Djc_version=jc305 build_m
JAVA_HOME=/path/to/jdk-11 ant -Djc_version=jc305 build_d
```

`jc_version`を省略した単体ビルドは`jc305`です。Java Card 3.1.0には固定submodule内の`jc310r20210706_kit`を使用します。共通ソースはビルド時にM/Dそれぞれのパッケージへコピーされるため、追加の共通ライブラリCAPは不要です。

SDKおよびAPI exportファイルには別途ライセンスが適用されます。[第三者依存](THIRD_PARTY_NOTICES.md)を参照してください。

## インストールと初期設定

対象カードに対応するGlobalPlatformのインストーラーを使用し、必要なSecurity Domain配下へCAPをインストールしてください。ホスト側のインストーラー・管理クライアントはこのリポジトリに含みません。

GP INSTALLのアプリケーションパラメータ（`C9`の値）には、次のTLVを連結して渡します。個数フィールドはありません。

```text
C1 14 <20バイトのSHA-1> C1 20 <32バイトのSHA-256> ...
```

先頭からスロット0、1、…に格納されます。パラメータを省略すると許可エントリは作成されません。ハッシュはASCII文字列ではなくバイト列として指定してください。インストーラーがHEX入力を受け付ける場合は、その形式に従ってください。

登録可能な初期エントリ数はINSTALL APDUの長さ制限にも依存します。収まらないエントリは、インストール後にSCP03で追加してください。CAPを削除・再インストールすると、保存済みルールは失われます。

### 全許可エントリ

`C1 00`を指定すると、証明書を限定しない全許可エントリになります。1スロットを使用します。全ゼロの20/32バイトハッシュは通常の証明書ハッシュとして扱い、全許可へ変換しません。

| 種別 | 全許可エントリが生成するルール |
| --- | --- |
| ARA-M | `E20BE1044F00C100E303D00101`。全SEアプリ・全デバイスアプリ向けのAPDUアクセス許可 |
| ARA-D | `E210E102C100E30ADB080000000100010001`。全デバイスアプリへDevice API権限マスクを適用 |

全許可エントリはアプリを限定せずにアクセスを許可します。特定アプリだけを許可する構成では、実際の署名証明書ハッシュを登録してください。

ARA-Dの全許可は64ビットの権限マスクをすべて1にする意味ではありません。AndroidのCarrier Privilegesは実際の証明書ハッシュを要求するため、ARA-Mの全許可では空ハッシュのCarrier Privilegesルールを生成しません。必要なアプリのハッシュを別スロットに登録してください。[Androidの説明](https://source.android.com/docs/core/connect/uicc#faq)

全許可を入れても、管理APDUにはSCP03認証が必要です。空リスト（`FF4000`）は許可なしを表します。

## 管理APDU

以下は論理チャネル0での表記です。SCP03の`INITIALIZE UPDATE` / `EXTERNAL AUTHENTICATE`は、対象ARAアプレットをSELECTした後に実行します。Security Domainで認証してからARAをSELECTする方式では、ARAのセッション認証にはなりません。

| 操作 | 平文APDU / データ | 応答 |
| --- | --- | --- |
| 全ルール | `80 CA FF 40 00` | `FF40 <BER長> <E2ルール列>` |
| 続きのルール | `80 CA FF 60 00` | 前回応答に続くバイト列 |
| Refresh Tag | `80 CA DF 20 00` | `DF20 08 <8バイト>` |
| 構成 | `80 CA DF 21 07 E405E603010100 00` | M: `DF2107E505E603010100`、D: `DF2107E505E603010000` |
| ハッシュ一覧 | `80 CA DF 22 00` | `DF22 <BER長> (E2 <長> 8001<slot> C1<len><hash>)*` |
| ハッシュ追加 | `80 E2 01 <slot> <Lc> C1<len><hash>` | 空きスロットに追加 |
| ハッシュ変更 | `80 E2 02 <slot> <Lc> C1<len><hash>` | 既存スロットを置換 |
| ハッシュ削除 | `80 E2 03 <slot>` | 既存スロットを削除 |
| GET RESPONSE | `00 C0 00 00 <Le>` | `61xx`で通知された残りのデータ |

変更系APDUは表の平文をSCP03でラップして送信します。そのまま送信すると`6982`です。`slot`は1バイトです。`len`は`00`（全許可）、`14`（SHA-1）、`20`（SHA-256）、対応する`Lc`は`02`、`16`、`22`（いずれもHEX）です。

`GET DATA All/Next`は最大256バイトずつ返し、各ブロックのSWは`9000`です。最初の`FF40`のBER長に達するまで`FF60`を送ります。ハッシュ一覧や短いLeでのRefresh Tag取得は`61xx` / `GET RESPONSE`で継続します。`DF21`はSELECT直後のみ受け付け、T=0に対応するため`610A`を返してGET RESPONSEを要求します。読み出し途中にルールが更新されると`FF60`は`6984`となり、`FF40`から読み直します。

| SW | 意味 |
| --- | --- |
| `9000` | 成功 |
| `61xx` | GET RESPONSEで継続（`6100`は256バイト以上） |
| `6700` | コマンドデータの長さ不正 |
| `6884` | コマンドチェイニング非対応 |
| `6982` | SCP03未認証、平文の変更コマンド、またはセキュリティ条件不成立 |
| `6984` | 分割取得中にルールが変更された |
| `6985` | スロット使用済み、重複ハッシュ、継続データなし、または構成取得順序不正 |
| `6A80` | TLVまたはハッシュ長が不正 |
| `6A86` | 操作番号、スロット番号、P1/P2が不正 |
| `6A88` | 変更・削除対象のスロットが空 |
| `6D00` / `6E00` | 未対応INS / CLA |

認証・MAC検証エラーの詳細SWはカードOSのGPサービスに依存します。

## シミュレーター試験とCI

シミュレーター試験にはJDK 17以降、curl、sha256sumを使用します。

```sh
bash tests/run.sh
```

初回実行時に固定バージョンのjCardSimをダウンロードし、SHA-256を照合します。インストールパラメータ、空リスト、全許可、16枠の操作、TLV、分割応答、リセット後の保持、不正入力、認証拒否経路を検証します。

GPサービスはテスト専用の代替実装です。実際のSCP03暗号処理、実カードの電源断耐性、Android側の権限適用を検証するものではありません。`tests/support`はCAPに含まれません。

[GitHub Actions](.github/workflows/build.yaml)では、6構成のCAPビルド・オフカード検証とシミュレーター試験を実行します。各ビルド成果物にはCAP、JAR、SHA-256チェックサム、ライセンス関連ファイルを含めます。CIに実カードやSCP03鍵は不要です。

## ライセンス

Copyright 2025-2026 COMMON CREATION, Co., Ltd.

このリポジトリの自作コードとドキュメントは[Apache License 2.0](LICENSE)で提供します。[NOTICE](NOTICE)および[第三者依存のライセンス](THIRD_PARTY_NOTICES.md)も参照してください。

## 仕様の参照

- [Android: UICC carrier privileges](https://source.android.com/docs/core/connect/uicc)
- [GlobalPlatform Secure Element Access Control v1.1](https://globalplatform.org/wp-content/uploads/2014/10/GPD_SE_Access_Control_v1.1.pdf)
- [GlobalPlatform Device API Access Control v1.0](https://globalplatform.org/specs-library/globalplatform-device-technology-device-api-access-control-v1/)
