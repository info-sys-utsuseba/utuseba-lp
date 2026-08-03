#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
[映せば会社環境] 受託開発セキュリティ検出エンジン（単一実体）
=============================================================
Partner-Link incident (2026-07-30) を受けて作成。
PUBLICリポの docs/ に LINE公式アカウントの生チャットログ（第三者25名分・要配慮個人情報含む）が
100日間コミットされていた。原因は「秘密情報はコードの中にある」という思い込みで、
資格情報パターンをコード拡張子にだけ grep していたこと。

■ 設計原則
 1. 検出器はここ1つだけ。呼び出し口（enforcement point）を3つ持つ:
      ① Claude の PreToolUse   → sec_guard.py       （AI経由のcommit/add）
      ② 実 git の pre-commit    → pre-commit        （人間・他の開発者のcommit）
      ③ vault の autopush      → vault_autopush.sh （自動push経路）
    どこか1つを迂回されても他で止まる。受託開発では開発者が情シス以外にもいるため②が必須。
 2. **検出値を絶対に出力しない。** file:line と パターン名 と 件数 だけ。
    レポート自体が二次漏洩になる事故を防ぐ（これは実際に起きうる）。
 3. BLOCK と WARN を分ける。機械的に確定するものだけ BLOCK。
    誤検知で開発が止まるとゲートは即座に無効化されるので、WARN の設計が生命線。
 4. **fail-open。** 例外が出たら黙って通す（exit 0）。セキュリティゲートが
    開発を人質に取ってはならない。止めるのは「確実に危ないと判定できたとき」だけ。

■ 終了コード
   0 = clean / 1 = WARN のみ / 2 = BLOCK あり
■ 出力（stdout, JSON）
   {"block":[{f,line,rule,sev,msg}], "warn":[...], "scanned":N, "skipped":N}
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------- 設定

MAX_BYTES = 1_500_000          # これより大きいファイルは読まない
CONTEXT_EXT_DOCS = {".md", ".txt", ".csv", ".tsv", ".json", ".yml", ".yaml",
                    ".html", ".htm", ".rst", ".org", ".log"}

# 「生エクスポートの原本」になり得る拡張子。ファイル名ルールはここに限定する。
# db/migrations/..._help_chat_logs.sql のような *コード* は、名前に chat_logs を
# 含んでもテーブル定義であって預かりデータではない（実測での誤検知）。
DATA_EXT = {".md", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".xml", ".log",
            ".xlsx", ".xls", ".numbers", ".pdf", ".zip", ".html", ".htm", ""}

# 走査対象外（ノイズ源・生成物）
SKIP_DIR_PARTS = (
    "/.git/", "/node_modules/", "/.next/", "/dist/", "/build/", "/out/",
    "/vendor/", "/.venv/", "/venv/", "/__pycache__/", "/.pytest_cache/",
    "/coverage/", "/.turbo/", "/.cache/", "/CLAUDE-SECURITY-",
)
SKIP_BASENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Gemfile.lock", "composer.lock", "Cargo.lock", "go.sum", "uv.lock",
}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".mp4", ".mov", ".mp3", ".wav",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".psd", ".ai", ".sketch",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".db", ".sqlite",
    ".pyc", ".so", ".dylib", ".dll", ".exe", ".wasm", ".map",
}

# ------------------------------------------------- BLOCK: 秘密情報
# 「これが平文でリポに入ったら事故が確定するもの」だけ。桁数まで縛って誤検知を消す。
SECRET_RULES = [
    ("secret.jwt",          re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JWT らしき3セグメントのトークン"),
    ("secret.openai",       re.compile(r"\bsk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{24,}"),
     "OpenAI/Anthropic 系 APIキー"),
    ("secret.github_pat",   re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}"),
     "GitHub Personal Access Token"),
    ("secret.aws",          re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWS アクセスキーID"),
    ("secret.gcp_apikey",   re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "Google API キー"),
    ("secret.slack",        re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
     "Slack トークン"),
    ("secret.stripe_live",  re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
     "Stripe 本番シークレットキー"),
    ("secret.privatekey",   re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "秘密鍵ブロック"),
    ("secret.line_channel", re.compile(r"(?i)channel[_-]?(?:secret|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{24,}"),
     "LINE チャネルシークレット/アクセストークン"),
    # service_role は「語」だけなら設計コメントで頻出するので、鍵らしき値と同居する場合のみ
    ("secret.supabase_srv", re.compile(r"(?i)(?:service[_-]?role|SUPABASE_SERVICE)[A-Z_]*\s*[:=]\s*['\"]?eyJ[A-Za-z0-9_-]{10,}"),
     "Supabase service_role キー（RLSを完全に迂回する）"),
]

# ------------------------------------------------- BLOCK: 権限そのものが漏れるURL
# 「URLを持っていること＝入室/閲覧許可」のもの。所持が認可なので、公開＝権限配布。
CAPABILITY_RULES = [
    ("cap.line_group",   re.compile(r"line\.me/ti/g2?/[A-Za-z0-9_-]{6,}"),
     "LINEグループ招待リンク（所持＝入室許可。友だち追加 ti/p/ とは別物）"),
    ("cap.line_openchat", re.compile(r"line\.me/ti/oc/[A-Za-z0-9_-]{6,}"),
     "LINE オープンチャット招待リンク"),
]

# ------------------------------------------------- BLOCK: 生エクスポートのファイル名
# 中身を読む前にファイル名で落とす。人間が付ける名前は正直なので、実は精度が高い。
RAWEXPORT_NAME = re.compile(
    r"(全チャットログ|チャットログ|全ログ|生データ|生ログ|rawdata|raw[_-]?log|"
    r"chat[_-]?(?:log|export|history)|message[_-]?export|会話ログ|"
    r"問い合わせ一覧|顧客一覧|名簿|回答一覧|応募者一覧)", re.IGNORECASE)

# ------------------------------------------------- WARN: 個人情報の兆候
PII_RULES = [
    ("pii.jp_mobile", re.compile(r"(?<![0-9-])0[789]0[-\s]?\d{4}[-\s]?\d{4}(?![0-9])"),
     "日本の携帯電話番号"),
    ("pii.jp_tel",    re.compile(r"(?<![0-9-])0(?![789]0)\d{1,3}[-(]\d{2,4}[-)]\d{4}(?![0-9])"),
     "日本の固定電話番号"),
    ("pii.email",     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "メールアドレス"),
    ("pii.mynumber",  re.compile(r"(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)"),
     "12桁の数字列（マイナンバーの形）"),
    ("pii.jp_address", re.compile(r"〒\s*\d{3}[-\s]?\d{4}"),
     "郵便番号を伴う住所"),
]
# メールの除外（テスト用・自明な非PII）
EMAIL_IGNORE = re.compile(
    r"@(?:example\.(?:com|jp|org|net)|test\.|localhost|invalid|"
    r"sentry\.io|users\.noreply\.github\.com)|"
    r"^(?:noreply|no-reply|do-not-reply|postmaster|webmaster|admin|root|test|dummy|sample|foo|bar)@",
    re.I)

# ------------------------------------------------- WARN: 要配慮個人情報の兆候
# 「障害」「不具合」は開発文脈で常用されるため絶対に入れない。医療文脈に限定した語だけ。
SENSITIVE_RULES = [
    ("sensitive.health", re.compile(
        r"(診断書|既往症|既往歴|持病|通院|入院|退院|疾病|傷病|うつ病|鬱病|"
        r"休職|療養|妊娠|出産予定|服薬|投薬|カルテ|要介護|障がい者手帳|障害者手帳)"),
     "健康・医療に関する記述（要配慮個人情報／APPI・GDPR Art.9）"),
    ("sensitive.social", re.compile(r"(前科|逮捕歴|被害届|信条|宗教|国籍|人種|出身地|支持政党|労働組合)"),
     "要配慮個人情報の類型（信条・社会的身分など）"),
    # 口語の健康状態。Partner-Link の実データは「診断書」ではなく
    # 「ご体調優れない」「体調があまり良くない」と書かれていた。医療用語だけを
    # 見張っていると、実際のチャットログの要配慮情報を丸ごと取りこぼす。
    # ただし日報・議事録では「体調不良で欠席」が日常語なので、
    # RAWEXPORT_ONLY（＝生エクスポートらしいファイル）に限定して評価する。
    ("sensitive.health_casual", re.compile(
        r"(体調(?:が?[^\n]{0,4}(?:優れ|すぐれ|良くな|よくな|悪|崩)|不良|不安定)|"
        r"ご体調|お加減|具合が悪|病院[へにで]|検査(?:結果|入院)|手術|薬を飲)"),
     "個人の健康状態に関する記述（要配慮個人情報／APPI 第2条3項）"),
]

# ------------------------------------------------- WARN: リンク共有URL
SHARELINK_RULES = [
    ("share.gdrive",  re.compile(r"drive\.google\.com/(?:file/d/|drive/(?:u/\d+/)?folders/)[A-Za-z0-9_-]{10,}"),
     "Google Drive 共有URL（リンクを知る全員が対象の可能性）"),
    ("share.gdocs",   re.compile(r"docs\.google\.com/(?:document|spreadsheets|presentation|forms)/d/[A-Za-z0-9_-]{20,}"),
     "Google ドキュメント/スプレッドシート共有URL"),
    ("share.vimeo",   re.compile(r"vimeo\.com/\d{6,}/[0-9a-f]{6,}"),
     "Vimeo 限定公開URL（ハッシュ部分が唯一の鍵）"),
    ("share.loom",    re.compile(r"loom\.com/share/[0-9a-f]{16,}"),
     "Loom 共有URL"),
    ("share.notion",  re.compile(r"notion\.(?:so|site)/[A-Za-z0-9-]*[0-9a-f]{32}"),
     "Notion 公開/共有ページURL"),
    ("share.manus",   re.compile(r"manus\.(?:im|space|ai)/share/[A-Za-z0-9_-]{8,}"),
     "Manus 共有ドキュメントURL"),
    ("share.dropbox", re.compile(r"(?:dropbox\.com/s(?:cl)?/|1drv\.ms/|box\.com/s/)[A-Za-z0-9_/-]{8,}"),
     "Dropbox/OneDrive/Box 共有URL"),
]

# ------------------------------------------------- WARN: インフラの露出
INFRA_RULES = [
    ("infra.public_ip", re.compile(
        r"(?<![\d.])(?!0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|22[4-9]\.|2[3-5]\d\.)"
        r"(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
     "グローバルIPアドレス（本番サーバの所在が推測できる）"),
]


# マイナンバーの重大度を引き上げる文脈語。ファイル全体のどこかに在れば足りる
# （CSVならヘッダ行、書類なら見出しに出て、値の行には出ないため）。
MYNUMBER_CONTEXT = re.compile(
    r"(マイナンバー|個人番号|my[_ -]?number|個人番号カード|通知カード|特定個人情報)", re.I)


def _rule_table():
    tbl = {}
    for group, sev, rules in (
        ("secret", "BLOCK", SECRET_RULES),
        ("cap", "BLOCK", CAPABILITY_RULES),
        ("pii", "WARN", PII_RULES),
        ("sensitive", "WARN", SENSITIVE_RULES),
        ("share", "WARN", SHARELINK_RULES),
        ("infra", "WARN", INFRA_RULES),
    ):
        for name, rx, msg in rules:
            tbl[name] = (sev, rx, msg, group)
    return tbl


RULES = _rule_table()

# ---------------------------------------------------------------- 値の妥当性判定
# 正規表現で拾った候補を「本当に危険か」で絞る。ここが甘いとゲートが信用されなくなる。

def _jwt_is_dangerous(tok):
    """JWT のペイロードを覗いて role を見る。
    Supabase の anon キーは **公開前提**（NEXT_PUBLIC_ で配られる）ので止めない。
    service_role はRLSを丸ごと迂回する全権キーなので必ず止める。
    実測: customer-record の e2e スクリプト10本が anon キーで、全部誤検知だった。"""
    try:
        import base64
        seg = tok.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
    except Exception:
        return True                      # 読めない＝判断できない＝安全側に倒す
    role = str(payload.get("role", "")).lower()
    if role in ("anon", "authenticated"):
        return False
    return True


def _phone_is_real(tok):
    """フォームの placeholder と実在番号を分ける。
    実測: shinsei-kiban の 7件はすべて `090-1234-5678` 等の入力例だった。
    連番・ゾロ目・末尾8桁が 12345678 のものは実在しない見本とみなす。"""
    d = re.sub(r"\D", "", tok)
    body = d[-8:]
    if len(set(body)) <= 2:                       # 00000000 / 11112222 など
        return False
    if body in ("12345678", "23456789", "87654321", "11223344"):
        return False
    if d.startswith(("0312345678", "0612345678", "0120")):
        return False
    return True


def _mynumber_is_valid(tok):
    """マイナンバーは12桁目が検査用数字。式に合わない12桁は別物（ID・ハッシュ・連番）。
    実測: 検出された2件はどちらもランダムな12桁IDで、検査桁が合わなかった。"""
    d = re.sub(r"\D", "", tok)
    if len(d) != 12:
        return False
    body = d[:11]
    total = 0
    for n in range(1, 12):                        # n = 下位からの桁位置
        p = int(body[11 - n])
        q = n + 1 if n <= 6 else n - 5
        total += p * q
    rem = total % 11
    check = 0 if rem <= 1 else 11 - rem
    return check == int(d[11])


def _keep(name, matched):
    """True なら検出として採用する。"""
    if name == "pii.email":
        return not EMAIL_IGNORE.search(matched)
    if name == "secret.jwt":
        return _jwt_is_dangerous(matched)
    if name in ("pii.jp_mobile", "pii.jp_tel"):
        return _phone_is_real(matched)
    if name == "pii.mynumber":
        return _mynumber_is_valid(matched)
    return True


# WARN 群のうち、ドキュメント系拡張子に限って評価するもの（コード内の誤検知を消す）
DOCS_ONLY = {"sensitive.health", "sensitive.social", "pii.mynumber", "pii.jp_tel"}

# さらに絞り、「外部データの生エクスポートらしいファイル」でのみ評価するもの。
# 日常語に近く単独では誤検知源になるが、顧客ログの中にあれば要配慮個人情報そのもの。
RAWEXPORT_ONLY = {"sensitive.health_casual"}


# ---------------------------------------------------------------- ユーティリティ

def _run(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=25)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except Exception:
        return 1, ""


def _git(args, cwd=None):
    """git を必ず core.quotePath=false で呼ぶ。
    既定の git は非ASCIIパスを "\\346\\227\\245..." のように八進エスケープした
    ダブルクォート付き文字列で返す。日本語ファイル名（＝生エクスポート原本の
    典型）がそのまま取りこぼされるため、ここを共通化して事故を防ぐ。"""
    return _run(["git", "-c", "core.quotePath=false"] + args, cwd=cwd)


def _git_paths(args, cwd=None):
    """-z（NUL区切り）でパス一覧を取る。空白・改行・日本語を含むパスに安全。"""
    rc, out = _git(args + ["-z"], cwd=cwd)
    if rc != 0:
        return []
    return [p for p in out.split("\0") if p.strip()]


def repo_root(start):
    rc, out = _run(["git", "rev-parse", "--show-toplevel"], cwd=start)
    return out.strip() if rc == 0 and out.strip() else None


def should_skip(path):
    p = "/" + path.replace(os.sep, "/").lstrip("/")
    for part in SKIP_DIR_PARTS:
        if part in p:
            return True
    base = os.path.basename(path)
    if base in SKIP_BASENAMES:
        return True
    ext = os.path.splitext(base)[1].lower()
    if ext in SKIP_EXT:
        return True
    return False


def load_allowlist(root):
    """.security/allow.txt — 1行 = 'ルール名' か 'パス接頭辞::ルール名'。
    誤検知でゲートが無効化されるのを防ぐための逃げ道。理由をコメントで残す運用。"""
    allow = set()
    if not root:
        return allow
    f = os.path.join(root, ".security", "allow.txt")
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    allow.add(line)
    except Exception:
        pass
    return allow


def allowed(allow, path, rule):
    if rule in allow:
        return True
    for entry in allow:
        if "::" in entry:
            pref, r = entry.split("::", 1)
            if r.strip() == rule and path.startswith(pref.strip()):
                return True
    return False


def load_registry():
    """案件レジストリ（受託開発の分類台帳）。

    台帳が「無い」のは設計上の正常系（CI・外部開発者の環境には同梱しない。
    顧客名の一覧を納品リポへ入れないため — README「CI で見ないもの」参照）。
    一方「有るのに読めない」は壊れた状態で、黙って案件間混入の検出だけが落ちる。
    検出しているつもりで何も見ていない状態になるので、必ず声を出す。
    """
    for cand in (os.environ.get("JOSYS_SEC_REGISTRY"),
                 os.path.expanduser("~/utsuseba/情シス基盤/security/repo-registry.json")):
        if not cand or not os.path.exists(cand):
            continue
        try:
            with open(cand, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as e:
            sys.stderr.write(
                "⚠️  案件台帳が読めません: %s\n"
                "    %s\n"
                "    このコミットでは案件間のデータ混入を検出できていません。\n"
                "    台帳を直してから再度コミットしてください。\n" % (cand, e))
            return {}
    return {}


# ---------------------------------------------------------------- 検出本体

def scan_text(path, text, allow, extra_rules=()):
    """1ファイル分のテキストを走査。**マッチした文字列は返さない。**"""
    hits = []
    ext = os.path.splitext(path)[1].lower()
    is_doc = ext in CONTEXT_EXT_DOCS
    is_rawexport = bool(RAWEXPORT_NAME.search(os.path.basename(path)))
    lines = text.split("\n")

    active = []
    for name, (sev, rx, msg, group) in RULES.items():
        if name in RAWEXPORT_ONLY and not is_rawexport:
            continue
        if name in DOCS_ONLY and not is_doc:
            continue
        if allowed(allow, path, name):
            continue
        active.append((name, sev, rx, msg))
    for name, sev, rx, msg in extra_rules:
        if not allowed(allow, path, name):
            active.append((name, sev, rx, msg))

    # マイナンバーは番号法で通常の個人情報より厳しく扱われる（特定個人情報）。
    # ただし12桁の数字は検査用数字が 1/11 の確率で偶然一致するため、形だけで止めると
    # 受注番号やタイムスタンプで誤停止する。「個人番号」等の文脈語が同居するときだけ
    # BLOCK へ引き上げる。精度を落とさずに重大度を上げるための条件。
    mynumber_ctx = bool(MYNUMBER_CONTEXT.search(text))

    counts = {}
    for i, line in enumerate(lines, 1):
        if len(line) > 4000:
            line = line[:4000]
        for name, sev, rx, msg in active:
            m = rx.search(line)
            if not m:
                continue
            if not _keep(name, m.group(0)):
                continue
            if name == "pii.mynumber" and (mynumber_ctx or is_rawexport):
                sev, msg = "BLOCK", msg + "／文脈から特定個人情報と判断（番号法）"
            key = (name, sev, msg)
            c = counts.get(key)
            if c is None:
                counts[key] = {"first": i, "n": 1}
            else:
                c["n"] += 1

    # 要配慮情報は「個人が特定できる情報」と結びついて初めて要配慮個人情報になる。
    # 仕様書の「休職者フラグ」「業種=宗教法人」は語彙であって個人データではない。
    # 同一ファイルに個人識別子が無く、生エクスポートでもないなら落とす。
    # （実測: customer-record の設計書で sensitive.health が72件出て、全部が語彙だった）
    has_identifier = is_rawexport or any(
        n.startswith("pii.") for (n, _s, _m) in counts)
    if not has_identifier:
        counts = {k: v for k, v in counts.items()
                  if not k[0].startswith("sensitive.")}

    for (name, sev, msg), agg in counts.items():
        hits.append({"file": path, "line": agg["first"], "rule": name,
                     "sev": sev, "msg": msg, "count": agg["n"]})
    return hits


def check_filename(path, allow):
    hits = []
    base = os.path.basename(path)
    if os.path.splitext(base)[1].lower() not in DATA_EXT:
        return hits          # コードファイルの名前は預かりデータの証拠にならない
    if RAWEXPORT_NAME.search(base) and not allowed(allow, path, "rawexport.filename"):
        hits.append({"file": path, "line": 0, "rule": "rawexport.filename",
                     "sev": "BLOCK", "count": 1,
                     "msg": "外部データの生エクスポートらしいファイル名。"
                            "加工前の原本をリポジトリに置いてはならない（Partner-Link と同型）"})
    return hits


def client_rules(root, registry):
    """案件間混入の検出。受託開発固有の最大リスク。
    このリポの顧客以外の顧客名が本文に出たら WARN。"""
    if not root or not registry:
        return []
    repos = registry.get("repos", {})
    me = repos.get(os.path.basename(root), {})
    my_client = me.get("client")
    out = []
    for cl in registry.get("clients", []):
        name = cl.get("name")
        if not name or name == my_client:
            continue
        # crossclient:false は「顧客ではない区分」。"自社" のような一般語を
        # 検出語にすると全案件リポで鳴り続け、警告そのものが無視されるようになる。
        # 鳴りすぎる検出は、鳴らない検出と同じくらい危険。
        if cl.get("crossclient") is False:
            continue
        aliases = [name] + list(cl.get("aliases", []))
        pat = "|".join(re.escape(a) for a in aliases if a)
        if not pat:
            continue
        out.append((
            "crossclient." + (cl.get("code") or name),
            "WARN",
            re.compile(pat),
            "他案件（%s）の顧客名が出現。案件間のデータ混入は受託契約違反に直結する" % name,
        ))
    return out


def scan_files(root, rel_paths, allow, extra):
    block, warn, scanned, skipped = [], [], 0, 0
    for rel in rel_paths:
        if not rel or should_skip(rel):
            skipped += 1
            continue
        full = os.path.join(root, rel) if root else rel
        hits = check_filename(rel, allow)
        try:
            if os.path.getsize(full) > MAX_BYTES:
                skipped += 1
                hits and _bucket(hits, block, warn)
                continue
            with open(full, "rb") as fh:
                raw = fh.read()
            if b"\x00" in raw[:4096]:
                skipped += 1
                hits and _bucket(hits, block, warn)
                continue
            text = raw.decode("utf-8", "replace")
        except Exception:
            skipped += 1
            hits and _bucket(hits, block, warn)
            continue
        scanned += 1
        hits.extend(scan_text(rel, text, allow, extra))
        _bucket(hits, block, warn)
    return block, warn, scanned, skipped


def _scan_diff(root, base, allow, extra):
    """diff の *追加行だけ* を見る共通処理。既存の負債で新しい変更を止めない。

    base は git diff の引数列（例 ["diff","--cached"] / ["diff","A..B"]）。
    staged（ローカル）と range（CI）で同じ判定が出ることを保証するため一本化している。
    """
    rel_paths = _git_paths(base + ["--name-only",
                                   "--diff-filter=ACMR"], cwd=root)
    block, warn, scanned, skipped = [], [], 0, 0

    for rel in rel_paths:
        if should_skip(rel):
            skipped += 1
            continue
        hits = check_filename(rel, allow)
        rc, diff = _git(base + ["-U0", "--", rel], cwd=root)
        if rc != 0:
            _bucket(hits, block, warn)
            continue
        added, lineno = [], 0
        for dl in diff.split("\n"):
            if dl.startswith("@@"):
                m = re.search(r"\+(\d+)", dl)
                lineno = int(m.group(1)) if m else 0
                continue
            if dl.startswith("+") and not dl.startswith("+++"):
                added.append((lineno, dl[1:]))
                lineno += 1
        if added:
            scanned += 1
            text = "\n".join(a[1] for a in added)
            for h in scan_text(rel, text, allow, extra):
                idx = min(h["line"] - 1, len(added) - 1)
                h["line"] = added[idx][0]
                hits.append(h)
        _bucket(hits, block, warn)
    return block, warn, scanned, skipped


def scan_staged(root, allow, extra):
    """staged な変更の追加行のみ（強制点①②＝ローカル）。"""
    return _scan_diff(root, ["diff", "--cached"], allow, extra)


def scan_range(root, rng, allow, extra):
    """コミット範囲の追加行のみ（強制点④＝CI）。

    rng は "BASE..HEAD"。BASE が空/全ゼロ（新規ブランチのpush）や解決不能なら
    追跡ファイル全体へフォールバックする。CIでは *黙って何も見ない* が最悪なので、
    範囲が取れないときは広く見る側に倒す。
    """
    base = rng.split("..")[0] if ".." in rng else ""
    bad = (not base) or set(base) <= {"0"} \
        or _git(["rev-parse", "--verify", "--quiet", base + "^{commit}"], cwd=root)[0] != 0
    if bad:
        return scan_files(root, _git_paths(["ls-files"], cwd=root), allow, extra)
    return _scan_diff(root, ["diff", rng], allow, extra)


def _bucket(hits, block, warn):
    for h in hits:
        (block if h["sev"] == "BLOCK" else warn).append(h)
    hits.clear()


# ---------------------------------------------------------------- 整形

def render(block, warn, *, root=None, mode=""):
    """人間とClaudeに読ませる本文。**検出値は一切含めない。**"""
    out = []
    if block:
        out.append("🔴 コミット/送信を停止しました（%d件）" % len(block))
        out.append("")
        for h in block:
            loc = h["file"] if h["line"] == 0 else "%s:%d" % (h["file"], h["line"])
            out.append("  ✗ %s  [%s]%s" % (loc, h["rule"],
                                           "" if h["count"] < 2 else " ×%d" % h["count"]))
            out.append("      %s" % h["msg"])
        out.append("")
        out.append("これは 2026-07-30 の Partner-Link 事故（PUBLICリポに顧客の生チャットログが")
        out.append("100日間公開・要配慮個人情報を含む）を受けて設置したゲートです。")
        out.append("受託開発では預かったデータの漏洩が契約違反と委託先監督義務違反に直結します。")
        out.append("")
        out.append("■ 正しい直し方")
        out.append("  1. 生データ・鍵・招待リンクは **リポジトリから外す**（.gitignore ではなく削除）")
        out.append("  2. 原本はアクセス制御された場所へ。リポには匿名化済みの派生物だけを置く")
        out.append("  3. 鍵が本物なら **失効・再発行が先**。履歴から消すだけでは無意味")
        out.append("  4. 招待リンクは **再発行してメンバー監査**（所持がそのまま入室許可）")
        out.append("")
        out.append("■ 誤検知だった場合")
        out.append("  .security/allow.txt に理由コメント付きで1行足す（例: `docs/spec.md::pii.email  # 架空の例示`）")
        out.append("  緊急時は git commit --no-verify で1回だけ迂回（push 後に CI が同じ判定を出す）")
    if warn:
        if block:
            out.append("")
        out.append("🟡 要確認（%d件・停止はしません）" % len(warn))
        for h in warn:
            loc = h["file"] if h["line"] == 0 else "%s:%d" % (h["file"], h["line"])
            out.append("  ! %s  [%s]%s — %s" % (
                loc, h["rule"], "" if h["count"] < 2 else " ×%d" % h["count"], h["msg"]))
        out.append("  ※ 意図的なら .security/allow.txt へ。顧客の個人情報なら置き場所を見直すこと。")
    return "\n".join(out)


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="映せば 受託開発セキュリティ検出エンジン")
    ap.add_argument("--repo", default=".", help="対象リポジトリ（既定: カレント）")
    ap.add_argument("--staged", action="store_true", help="staged の追加行のみ走査")
    ap.add_argument("--files", nargs="*", help="指定ファイルを走査")
    ap.add_argument("--tracked", action="store_true", help="追跡中の全ファイルを走査（棚卸し用）")
    ap.add_argument("--range", help="コミット範囲の追加行のみ走査（CI用・例 BASE..HEAD）")
    ap.add_argument("--json", action="store_true", help="JSONだけ出力")
    ap.add_argument("--strict", action="store_true",
                    help="内部エラーで fail-open せず異常終了する（CI用）")
    a = ap.parse_args()

    try:
        start = os.path.abspath(a.repo)
        root = repo_root(start) or start
        allow = load_allowlist(root)
        extra = client_rules(root, load_registry())

        if a.staged:
            b, w, sc, sk = scan_staged(root, allow, extra)
        elif getattr(a, "range", None):
            b, w, sc, sk = scan_range(root, a.range, allow, extra)
        elif a.files:
            rels = []
            for f in a.files:
                af = os.path.abspath(f)
                rels.append(os.path.relpath(af, root) if af.startswith(root) else af)
            b, w, sc, sk = scan_files(root, rels, allow, extra)
        elif a.tracked:
            b, w, sc, sk = scan_files(
                root, _git_paths(["ls-files"], cwd=root), allow, extra)
        else:
            ap.error("--staged / --range / --files / --tracked のいずれかを指定")
            return 0

        if a.json:
            print(json.dumps({"block": b, "warn": w, "scanned": sc, "skipped": sk},
                             ensure_ascii=False))
        else:
            txt = render(b, w, root=root)
            if txt:
                print(txt)
            else:
                print("clean（走査 %d / 除外 %d）" % (sc, sk))
        return 2 if b else (1 if w else 0)
    except Exception:
        # ローカル(強制点①②③)は fail-open。ゲートの故障で開発を止めない。
        # CI(強制点④)は --strict で fail-closed。CIは開発を止めても止血が優先で、
        # かつ「壊れて常に通っている」状態が最も危険なので必ず気づける側に倒す。
        if getattr(a, "strict", False):
            import traceback
            traceback.print_exc()
            return 3
        return 0


if __name__ == "__main__":
    sys.exit(main())
