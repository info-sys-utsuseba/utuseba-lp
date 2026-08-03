#!/bin/sh
# このリポジトリに セキュリティ検査フックを入れる（このファイルはリポジトリに同梱されています）
#
#   sh .security/install-hook.sh
#
# 外部の開発者の方へ:
#   このリポジトリを clone したら、最初に1回だけ実行してください。
#   別のリポジトリを取ってくる必要はありません。必要なものは全部この中に入っています。
#
# なぜ必要か:
#   git の仕様上、フック（.git/hooks/）は clone しても付いてきません。
#   commit で運べるのはこのスクリプトまでで、設置は各自の手元で1回だけ必要です。
#   ※実行しなくても push 後に CI が同じ検査をします。手元で入れておくと、
#     顧客の情報が履歴に入る *前* に気づけます。
set -eu

ROOT="$(git rev-parse --show-toplevel)"
SEC="$ROOT/.security"

[ -f "$SEC/pre-commit" ] || { echo "❌ $SEC/pre-commit がありません。リポジトリの取得が不完全です"; exit 1; }
[ -f "$SEC/engine.py" ]  || { echo "❌ $SEC/engine.py がありません。リポジトリの取得が不完全です";  exit 1; }

command -v python3 >/dev/null 2>&1 || {
  echo "❌ python3 が見つかりません。先に python3 を入れてください"
  echo "   macOS: xcode-select --install / Windows: python.org から（Add to PATH）"
  exit 1
}

HK="$(git -C "$ROOT" rev-parse --git-path hooks)"
case "$HK" in /*) : ;; *) HK="$ROOT/$HK" ;; esac
mkdir -p "$HK"

# 既存の pre-commit（husky 等）は潰さず退避。フックは連鎖して実行する。
if [ -f "$HK/pre-commit" ] && ! grep -q josys-security "$HK/pre-commit" 2>/dev/null; then
  mv "$HK/pre-commit" "$HK/pre-commit.local"
  echo "⚠️  既存の pre-commit を pre-commit.local へ退避しました（引き続き実行されます）"
fi

cp "$SEC/pre-commit" "$HK/pre-commit"
chmod +x "$HK/pre-commit"

# core.hooksPath があると .git/hooks は完全に無視される。黙って無効化されるのを防ぐ。
HP="$(git -C "$ROOT" config --get core.hooksPath 2>/dev/null || true)"
if [ -n "$HP" ]; then
  echo "⚠️  core.hooksPath=$HP が設定されています。**この設定がある間フックは動きません**"
  echo "   解除: git config --unset core.hooksPath （または $HP 側に pre-commit を置く）"
  exit 1
fi

echo "✅ セキュリティ検査を設置しました: $HK/pre-commit"
echo "   以後 git commit のたびに、追加行だけが検査されます。"
