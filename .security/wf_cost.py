#!/usr/bin/env python3
"""josys-security — GitHub Actions コスト事故ゲート（強制点⑥）

2026-08-12 に info-sys-utsuseba の Actions 無料枠（月2,000分）が枯渇し、
請求書の提出チェックほか全社の自動処理が停止した。原因は一発の派手なミスではなく、
「1本ずつは小さいが、足すと枠を超える」ワークフローが各案件に積み上がったこと。

このゲートは *人が気をつける* ことをやめるための機械側の歯止め。
金額ではなく **実行回数** を見る。理由は GitHub の課金がジョブ単位で
**1分に切り上げ** られるため：5秒で終わる curl 1本でも 1分課金される。
つまり「ジョブを速くする」は 1円も効かず、効くのは「回数を減らす」ことだけ。

── 判定するもの ────────────────────────────────────────────
  CRON_TOO_OFTEN        cron の実行回数が多すぎる（毎時超え=BLOCK / 月250回超=WARN）
  NO_TIMEOUT            job に timeout-minutes が無い（既定360分。1本の暴走で枠の18%）
  PUSH_PR_BOTH          on: push と on: pull_request が両方無条件（同じ差分を2回課金）
  SCHEDULE_NO_CONCURRENCY  schedule なのに concurrency 無し（滞留分の一斉実行）

── 逃げ道 ──────────────────────────────────────────────────
  意図的な例外は、該当行またはその1行上に `# cost-ok: <理由>` を書く。
  理由の記述を必須にしているのは、無言の握り潰しを残さないため。

  例:
      # cost-ok: 振込期日の検知は遅延が許されない（笹生さん判断 2026-08-19）
      - cron: '45 * 18-26 * *'

使い方:
  python3 wf_cost.py --repo <リポジトリルート> [--files <yml>...] [--strict]
終了コード:
  0=問題なし  1=WARN のみ  2=BLOCK あり  それ以外=エンジン異常
"""

import argparse
import datetime
import os
import re
import sys

# 「毎時」を上限の目安に置く。毎時=744回/月。これを超えるものは、
# 原則として GitHub Actions ではなく外部の定時実行（Vercel Cron 等）へ出す。
BLOCK_RUNS_PER_MONTH = 750
WARN_RUNS_PER_MONTH = 250

# GitHub の job 既定タイムアウト。ここを明示しないと、ハングした 1 ジョブが
# 6 時間ぶん課金される（無料枠 2,000 分の 18%）。
GITHUB_DEFAULT_TIMEOUT_MIN = 360


# ---------------------------------------------------------------- YAML 最小読み

class Line:
    __slots__ = ("no", "indent", "key", "value", "raw", "is_item")

    def __init__(self, no, indent, key, value, raw, is_item):
        self.no = no
        self.indent = indent
        self.key = key
        self.value = value
        self.raw = raw
        self.is_item = is_item


def _strip_comment(s):
    """行末コメントを落とす。引用符の中の # は残す。"""
    out = []
    quote = None
    for ch in s:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def parse_lines(text):
    """ワークフロー YAML を「インデント・キー・値」の平坦な列にする。

    PyYAML を使わないのは、このゲートが外部開発者の手元（pre-commit）でも
    動く必要があり、そこに依存パッケージを増やしたくないため。
    見るのは決まった数個のキーだけなので、完全な YAML 解釈は要らない。
    """
    res = []
    for i, raw in enumerate(text.splitlines(), 1):
        body = _strip_comment(raw)
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        s = body.strip()
        is_item = s.startswith("- ")
        if is_item:
            s = s[2:].strip()
            indent += 2
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*(.*)$", s)
        if m:
            res.append(Line(i, indent, m.group(1), m.group(2).strip(), raw, is_item))
        else:
            res.append(Line(i, indent, None, s, raw, is_item))
    return res


def block_of(lines, idx):
    """lines[idx] の配下（より深いインデント）を返す。"""
    base = lines[idx].indent
    out = []
    for ln in lines[idx + 1:]:
        if ln.indent <= base:
            break
        out.append(ln)
    return out


def find_top(lines, key):
    """最上位（indent 0）の key を探して添字を返す。`on:` は YAML では真偽値
    として解釈され得るが、ここは生文字列で見ているので取り違えない。"""
    for i, ln in enumerate(lines):
        if ln.indent == 0 and ln.key == key:
            return i
    return -1


# ---------------------------------------------------------------- cron 展開

def _field(expr, lo, hi, names=None):
    """cron の 1 フィールドを取りうる値の集合へ展開する。"""
    vals = set()
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            part, _, st = part.partition("/")
            step = int(st)
            if step <= 0:
                raise ValueError("step は 1 以上")
        if part in ("*", "?"):
            start, end = lo, hi
        elif "-" in part.lstrip("-"):
            a, _, b = part.partition("-")
            start, end = _num(a, names), _num(b, names)
        else:
            start = end = _num(part, names)
            if step != 1:            # 「5/10」は 5,15,25... と解釈される
                end = hi
        if start > end:              # 例: 23-2（日をまたぐ）
            rng = list(range(start, hi + 1)) + list(range(lo, end + 1))
        else:
            rng = list(range(start, end + 1))
        for n, v in enumerate(rng):
            if n % step == 0:
                vals.add(v)
    if not vals:
        raise ValueError("空のフィールド")
    return vals


_MON = {m: i for i, m in enumerate(
    "jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
_DOW = {d: i for i, d in enumerate("sun mon tue wed thu fri sat".split())}


def _num(tok, names):
    tok = tok.strip()
    if names and tok.lower() in names:
        return names[tok.lower()]
    return int(tok)


def cron_runs_per_month(expr):
    """cron 式が 30 日で何回発火するかを数える。

    実際に分刻みで回して数える。式の書き方（*/5 か 0,5,10,... か、
    曜日と日の併用か）に左右されず、常に同じ答えになる方を選んだ。
    """
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron は 5 フィールド（分 時 日 月 曜）である必要があります")
    mi = _field(parts[0], 0, 59)
    hh = _field(parts[1], 0, 23)
    dom = _field(parts[2], 1, 31)
    mon = _field(parts[3], 1, 12, _MON)
    dow = _field(parts[4], 0, 7, _DOW)
    if 7 in dow:                       # 7 も日曜
        dow = (dow - {7}) | {0}
    dom_all = parts[2].strip() in ("*", "?")
    dow_all = parts[4].strip() in ("*", "?")

    # 起点は固定日にする。実行のたびに答えが変わると、CI の判定が揺れて信用されない。
    start = datetime.datetime(2027, 1, 1)
    count = 0
    t = start
    end = start + datetime.timedelta(days=30)
    step = datetime.timedelta(minutes=1)
    while t < end:
        if t.minute in mi and t.hour in hh and t.month in mon:
            wd = (t.weekday() + 1) % 7        # Python: 月=0 / cron: 日=0
            if dom_all and dow_all:
                ok = True
            elif dom_all:
                ok = wd in dow
            elif dow_all:
                ok = t.day in dom
            else:
                # 日と曜日が両方指定されたときは OR。crontab(5) の仕様。
                ok = (t.day in dom) or (wd in dow)
            if ok:
                count += 1
        t += step
    return count


# ---------------------------------------------------------------- 検査

class Hit:
    def __init__(self, sev, rule, line, msg, fix):
        self.sev = sev
        self.rule = rule
        self.line = line
        self.msg = msg
        self.fix = fix


def _cost_ok(src_lines, lineno):
    """該当行またはその 1 行上に `# cost-ok: 理由` があるか。理由の無い
    `# cost-ok` は逃げ道として認めない（無言の握り潰しを残さないため）。"""
    for n in (lineno, lineno - 1):
        if 1 <= n <= len(src_lines):
            m = re.search(r"#\s*cost-ok\s*:\s*(\S.*)$", src_lines[n - 1])
            if m and m.group(1).strip():
                return True
    return False


def check_workflow(path, text):
    src = text.splitlines()
    lines = parse_lines(text)
    hits = []

    def add(sev, rule, lineno, msg, fix):
        if _cost_ok(src, lineno):
            return
        hits.append(Hit(sev, rule, lineno, msg, fix))

    # ── on: の中身 ──
    oi = find_top(lines, "on")
    on_keys = {}
    if oi >= 0:
        inline = lines[oi].value
        if inline:                                   # `on: push` / `on: [push, pr]`
            for k in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", inline):
                on_keys[k] = []
        else:
            base = None
            for ln in block_of(lines, oi):
                if base is None:
                    base = ln.indent
                if ln.indent == base and ln.key:
                    on_keys[ln.key] = []
                elif ln.indent == base and ln.is_item and ln.value:
                    on_keys[ln.value.strip()] = []   # `on:` 直下の - push 形式

    # ── cron の頻度 ──
    for ln in lines:
        if ln.key != "cron":
            continue
        expr = ln.value.strip().strip("'\"")
        try:
            runs = cron_runs_per_month(expr)
        except Exception as e:
            add("BLOCK", "CRON_UNPARSABLE", ln.no,
                "cron 式を解釈できません（%s）: %s" % (e, expr),
                "5フィールド（分 時 日 月 曜）で書き直してください。")
            continue
        # 1 実行 = 最低 1 分課金。回数がそのまま分になる。
        if runs > BLOCK_RUNS_PER_MONTH:
            add("BLOCK", "CRON_TOO_OFTEN", ln.no,
                "cron '%s' は月 %d 回（最低 %d 分/月）。毎時（744回）を超えています。"
                % (expr, runs, runs),
                "・間隔を広げる（業務時間帯だけにするのも有効）\n"
                "      ・HTTP を叩くだけなら Vercel Cron 等へ出す（Actions 消費ゼロ）\n"
                "      ・どうしても必要なら該当行の上に `# cost-ok: <理由>` を書く")
        elif runs > WARN_RUNS_PER_MONTH:
            add("WARN", "CRON_FREQUENT", ln.no,
                "cron '%s' は月 %d 回（最低 %d 分/月）。無料枠 2,000 分の %d%% を使います。"
                % (expr, runs, runs, round(runs * 100 / 2000)),
                "本当にこの頻度が要るか一度確認してください。")

    # ── push と pull_request の二重掛け ──
    if "push" in on_keys and "pull_request" in on_keys:
        def unfiltered(key):
            for i, ln in enumerate(lines):
                if ln.key == key and oi >= 0 and ln.indent > lines[oi].indent:
                    return not any(x.key in ("branches", "branches-ignore",
                                             "paths", "paths-ignore")
                                   for x in block_of(lines, i))
            return True
        if unfiltered("push") and unfiltered("pull_request"):
            ln = next((x for x in lines if x.key == "pull_request"), None)
            add("BLOCK", "PUSH_PR_BOTH", ln.no if ln else 1,
                "on: push と on: pull_request が両方とも無条件です。"
                "PR ブランチへの push で同じ差分を 2 回走らせ、2 回課金されます。",
                "・同一リポ内の PR なら push 側だけで全コミットを見られます\n"
                "      → pull_request を外すのが最も無駄がありません\n"
                "      ・外部 PR も見るなら push に branches: [main, master] を付ける")

    # ── job ごとの timeout-minutes ──
    ji = find_top(lines, "jobs")
    if ji >= 0:
        jb = block_of(lines, ji)
        jbase = min((l.indent for l in jb), default=None)
        for n, ln in enumerate(jb):
            if ln.indent != jbase or not ln.key:
                continue
            body = block_of(jb, n)
            inner = min((x.indent for x in body), default=None)
            direct = [x for x in body if x.indent == inner]
            if any(x.key == "timeout-minutes" for x in direct):
                continue
            if any(x.key == "uses" for x in direct):
                continue           # 再利用ワークフロー呼び出し側では指定できない
            add("BLOCK", "NO_TIMEOUT", ln.no,
                "job '%s' に timeout-minutes がありません。既定は %d 分で、"
                "1 本ハングすると無料枠の %d%% を一度に失います。"
                % (ln.key, GITHUB_DEFAULT_TIMEOUT_MIN,
                   round(GITHUB_DEFAULT_TIMEOUT_MIN * 100 / 2000)),
                "実際の所要時間の 2〜3 倍を目安に `timeout-minutes: 10` を足してください。")

    # ── schedule なのに concurrency が無い ──
    if "schedule" in on_keys:
        has_top = find_top(lines, "concurrency") >= 0
        has_job = any(l.key == "concurrency" for l in lines)
        if not (has_top or has_job):
            add("WARN", "SCHEDULE_NO_CONCURRENCY", 1,
                "定期実行なのに concurrency がありません。前回が終わらないうちに"
                "次が始まり、遅延時に一斉実行されて分を余計に使うことがあります。",
                "concurrency:\n        group: <ワークフロー名>\n"
                "        cancel-in-progress: false")

    return hits


# ---------------------------------------------------------------- 出力

def render(results):
    block = [(p, h) for p, hs in results for h in hs if h.sev == "BLOCK"]
    warn = [(p, h) for p, hs in results for h in hs if h.sev == "WARN"]
    out = []
    if block:
        out.append("🔴 Actions のコスト事故につながる設定を検出しました（%d件）" % len(block))
        out.append("")
        for p, h in block:
            out.append("  ✗ %s:%d  [%s]" % (p, h.line, h.rule))
            out.append("      %s" % h.msg)
            out.append("      直し方: %s" % h.fix)
            out.append("")
        out.append("  2026-08-12 に無料枠（月2,000分）が枯渇し、請求書の提出チェックほか")
        out.append("  全社の自動処理が停止しました。課金はジョブ単位で1分に切り上げです。")
        out.append("  つまり処理を速くしても1円も減りません。減らせるのは実行回数だけです。")
        out.append("")
    if warn:
        out.append("🟡 確認してください（%d件・停止はしません）" % len(warn))
        for p, h in warn:
            out.append("  ・%s:%d  [%s] %s" % (p, h.line, h.rule, h.msg))
        out.append("")
    return "\n".join(out)


def collect(root, files):
    if files:
        return [f for f in files
                if re.search(r"\.github/workflows/[^/]+\.ya?ml$", f.replace("\\", "/"))]
    d = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(d):
        return []
    return sorted(os.path.join(".github", "workflows", n)
                  for n in os.listdir(d) if n.endswith((".yml", ".yaml")))


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--files", nargs="*", default=None,
                    help="対象を絞る（pre-commit 用・staged なワークフローだけ渡す）")
    ap.add_argument("--strict", action="store_true",
                    help="BLOCK があれば終了コード 2 を返す")
    a = ap.parse_args()

    root = os.path.abspath(a.repo)
    results = []
    for rel in collect(root, a.files):
        path = rel if os.path.isabs(rel) else os.path.join(root, rel)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        results.append((rel, check_workflow(rel, text)))

    body = render(results)
    if body:
        sys.stdout.write(body + "\n")

    has_block = any(h.sev == "BLOCK" for _, hs in results for h in hs)
    has_warn = any(h.sev == "WARN" for _, hs in results for h in hs)
    if has_block:
        return 2 if a.strict else 1
    return 1 if has_warn else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                       # 壊れて黙って通るのが最悪
        sys.stderr.write("wf_cost: 異常終了: %r\n" % (e,))
        sys.exit(3)
