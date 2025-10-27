#!/bin/sh
# tar-verify.sh
# Verify a manifest produced by tar-manifest.sh against the actual TAR archive.
# - Verifies archive-level hashes (sha256, sha512, blake3, xxh128, crc32) that are present in the manifest.
# - If per-entry hashes exist, verify each member by streaming (tar -xOf ... | hasher).
#
# Requirements: POSIX sh + tar + stat + date + awk + wc
# Optional tools auto-detected: sha256sum/sha512sum, openssl, b3sum, xxhsum, rhash, crc32, jq (for JSON manifest)
#
# Usage:
#   ./tar-verify.sh /path/to/foo.tar.manifest.txt
#   ./tar-verify.sh /path/to/foo.tar.manifest.json
#   ./tar-verify.sh --tar /override/path/foo.tar /path/to/foo.tar.manifest.txt
#
# Flags:
#   --tar <path>   Override TAR path recorded in the manifest
#   -v|--verbose   Verbose per-file output and progress
#   -h|--help      Show help
#
set -eu

show_help() {
  sed -n '1,120p' "$0" | sed 's/^# \{0,1\}//'
}

have() { command -v "$1" >/dev/null 2>&1; }
info() { if [ "${VERBOSE:-0}" -eq 1 ]; then printf "%s\n" "$*" >&2; fi; }

abs_path() {
  case "$1" in
    /*) printf "%s\n" "$1" ;;
    *)  printf "%s\n" "$(cd "$(dirname "$1")" 2>/dev/null && pwd)/$(basename "$1")" ;;
  esac
}

# --- portable stat helpers ---
stat_field() {
  what="$1"; file="$2"
  case "$what" in
    size)
      if stat -c %s "$file" >/dev/null 2>&1; then stat -c %s "$file"
      elif stat -f %z "$file" >/dev/null 2>&1; then stat -f %z "$file"; fi ;;
  esac
}

# --- archive hashing helpers (match tar-manifest.sh) ---
hash_sha() {
  algo="$1"; file="$2"
  case "$algo" in
    sha256)
      if have sha256sum; then sha256sum "$file" | awk '{print $1}'
      elif have openssl; then openssl dgst -sha256 -r "$file" | awk '{print $1}'
      elif have rhash; then rhash --sha256 "$file" --printf="%{sha256}\n"
      else echo "" ; fi ;;
    sha512)
      if have sha512sum; then sha512sum "$file" | awk '{print $1}'
      elif have openssl; then openssl dgst -sha512 -r "$file" | awk '{print $1}'
      elif have rhash; then rhash --sha512 "$file" --printf="%{sha512}\n"
      else echo "" ; fi ;;
  esac
}

hash_b3() {
  file="$1"
  if have b3sum; then b3sum "$file" | awk '{print $1}'
  elif have blake3; then blake3 hash "$file" | awk '{print $1}'
  elif have rhash; then rhash --blake3 "$file" --printf="%{blake3}\n"
  else echo "" ; fi
}

hash_xxh128() {
  file="$1"
  if have xxhsum; then xxhsum -H128 "$file" | awk '{print $1}'
  elif have rhash; then rhash --xxh128 "$file" --printf="%{xxh128}\n"
  else echo "" ; fi
}

hash_crc32() {
  file="$1"
  if have crc32; then crc32 "$file" 2>/dev/null | awk '{print $1}'
  elif have rhash; then rhash --crc32 "$file" --printf="%{crc32}\n"
  else echo "" ; fi
}

# per-stream hashing for entry verification
pipe_hash() {
  algo="$1"
  case "$algo" in
    sha256)
      if have sha256sum; then sha256sum | awk '{print $1}'
      elif have openssl; then openssl dgst -sha256 -r | awk '{print $1}'
      elif have rhash; then rhash --sha256 --stdin --printf="%{sha256}\n"
      else cat >/dev/null; echo "" ; fi ;;
    sha512)
      if have sha512sum; then sha512sum | awk '{print $1}'
      elif have openssl; then openssl dgst -sha512 -r | awk '{print $1}'
      elif have rhash; then rhash --sha512 --stdin --printf="%{sha512}\n"
      else cat >/dev/null; echo "" ; fi ;;
    xxh128)
      if have xxhsum; then xxhsum -H128 | awk '{print $1}'
      elif have rhash; then rhash --xxh128 --stdin --printf="%{xxh128}\n"
      else cat >/dev/null; echo "" ; fi ;;
  esac
}

# --- parse args ---
TAR_OVERRIDE=""
VERBOSE=0
MANIFEST=""

while [ "$#" -gt 0 ]; do
  case "${1:-}" in
    --tar) TAR_OVERRIDE="${2:-}"; shift ;;
    -v|--verbose) VERBOSE=1 ;;
    -h|--help) show_help; exit 0 ;;
    -*)
      echo "Unknown flag: $1" >&2; exit 2 ;;
    *)
      if [ -z "$MANIFEST" ]; then MANIFEST="$1"; else
        echo "Only one manifest path allowed." >&2; exit 2
      fi ;;
  esac
  shift
done

if [ -z "${MANIFEST:-}" ]; then
  echo "Usage: $0 [--tar /path/to/archive.tar] [-v] /path/to/manifest.(txt|json)" >&2
  exit 2
fi

if [ ! -f "$MANIFEST" ]; then
  echo "Not a file: $MANIFEST" >&2
  exit 2
fi

EXT="$(printf "%s" "$MANIFEST" | awk -F. '{print tolower($NF)}')"

# --- extract fields from manifest ---
ARC_PATH=""
M_SHA256=""; M_SHA512=""; M_BLAKE3=""; M_XXH128=""; M_CRC32=""
M_SIZE=""

ENTRY_ALGO=""
ENTRY_LINES_FILE=""

if [ "$EXT" = "json" ]; then
  if ! have jq; then
    echo "JSON manifest requires 'jq'. Install jq or use TXT manifest." >&2
    exit 3
  fi
  ARC_PATH="$(jq -r '.archive.path // empty' "$MANIFEST")"
  M_SIZE="$(jq -r '.archive.size_bytes // empty' "$MANIFEST")"
  M_SHA256="$(jq -r '.archive.hashes.sha256 // empty' "$MANIFEST")"
  M_SHA512="$(jq -r '.archive.hashes.sha512 // empty' "$MANIFEST")"
  M_BLAKE3="$(jq -r '.archive.hashes.blake3 // empty' "$MANIFEST")"
  M_XXH128="$(jq -r '.archive.hashes.xxh128 // empty' "$MANIFEST")"
  M_CRC32="$(jq -r  '.archive.hashes.crc32  // empty' "$MANIFEST")"

  ENTRY_ALGO="$(jq -r '.per_entry_hash_algo // empty' "$MANIFEST")"
  if [ -n "$ENTRY_ALGO" ]; then
    ENTRY_LINES_FILE="$(mktemp -t entrylines.XXXXXX)"
    jq -r '.per_entry_hashes_text // empty' "$MANIFEST" > "$ENTRY_LINES_FILE"
    if [ ! -s "$ENTRY_LINES_FILE" ]; then
      rm -f "$ENTRY_LINES_FILE"; ENTRY_LINES_FILE=""
    fi
  fi
else
  ARC_PATH="$(awk '
    BEGIN{s=0}
    /^\[archive\]/{s=1; next}
    /^\[/{if(s==1) exit}
    s==1 && $1=="path:"{ $1=""; sub(/^ /,""); print; exit}
  ' "$MANIFEST")"

  M_SIZE="$(awk '
    BEGIN{s=0}
    /^\[archive\]/{s=1; next}
    /^\[/{if(s==1) exit}
    s==1 && $1=="size_bytes:"{print $2; exit}
  ' "$MANIFEST")"

  M_SHA256="$(awk 'BEGIN{s=0}/^\[archive\]/{s=1;next}/^\[/{if(s==1)exit}s==1 && $1=="hash.sha256:"{print $2; exit}' "$MANIFEST")"
  M_SHA512="$(awk 'BEGIN{s=0}/^\[archive\]/{s=1;next}/^\[/{if(s==1)exit}s==1 && $1=="hash.sha512:"{print $2; exit}' "$MANIFEST")"
  M_BLAKE3="$(awk 'BEGIN{s=0}/^\[archive\]/{s=1;next}/^\[/{if(s==1)exit}s==1 && $1=="hash.blake3:"{print $2; exit}' "$MANIFEST")"
  M_XXH128="$(awk 'BEGIN{s=0}/^\[archive\]/{s=1;next}/^\[/{if(s==1)exit}s==1 && $1=="hash.xxh128:"{print $2; exit}' "$MANIFEST")"
  M_CRC32="$(awk 'BEGIN{s=0}/^\[archive\]/{s=1;next}/^\[/{if(s==1)exit}s==1 && $1=="hash.crc32:"{print $2; exit}' "$MANIFEST")"

  ENTRY_ALGO="$(awk '
    /^\[tar\.entry_hashes[[:space:]][a-z0-9]+\]$/{
      gsub(/^\[tar\.entry_hashes[[:space:]]/,"",$0);
      gsub(/\]$/,"",$0);
      print tolower($0); exit
    }' "$MANIFEST")"

  if [ -n "$ENTRY_ALGO" ]; then
    ENTRY_LINES_FILE="$(mktemp -t entrylines.XXXXXX)"
    awk '
      BEGIN{mode=0}
      /^\[tar\.entry_hashes[[:space:]][a-z0-9]+\]$/{mode=1; next}
      /^\[/{if(mode==1) exit}
      mode==1 {print}
    ' "$MANIFEST" > "$ENTRY_LINES_FILE"
    if [ ! -s "$ENTRY_LINES_FILE" ]; then rm -f "$ENTRY_LINES_FILE"; ENTRY_LINES_FILE=""; fi
  fi
fi

# allow override
if [ -n "${TAR_OVERRIDE:-}" ]; then ARC_PATH="$TAR_OVERRIDE"; fi
if [ -z "${ARC_PATH:-}" ]; then
  echo "Could not determine archive path from manifest. Use --tar to provide it." >&2
  exit 3
fi
ARC_PATH="$(abs_path "$ARC_PATH")"

if [ ! -f "$ARC_PATH" ]; then
  echo "Archive not found: $ARC_PATH" >&2
  exit 3
fi

echo "== Verifying archive =="
echo "Manifest : $MANIFEST"
echo "Archive  : $ARC_PATH"
RC=0

# size check (if available)
if [ -n "$M_SIZE" ]; then
  info "Checking size..."
  ACT_SIZE="$(stat_field size "$ARC_PATH" || echo "")"
  if [ "$M_SIZE" = "$ACT_SIZE" ]; then
    echo "[ OK ] size: $ACT_SIZE bytes"
  else
    echo "[FAIL] size: expected $M_SIZE got ${ACT_SIZE:-unknown}"
    RC=1
  fi
fi

# hash checks
verify_algo() {
  algo="$1"; expected="$2"
  [ -z "$expected" ] && return 0
  info "Computing $algo for archive..."
  case "$algo" in
    sha256) got="$(hash_sha sha256 "$ARC_PATH")" ;;
    sha512) got="$(hash_sha sha512 "$ARC_PATH")" ;;
    blake3) got="$(hash_b3 "$ARC_PATH")" ;;
    xxh128) got="$(hash_xxh128 "$ARC_PATH")" ;;
    crc32)  got="$(hash_crc32 "$ARC_PATH")" ;;
    *) got="" ;;
  esac
  if [ -z "$got" ]; then
    echo "[FAIL] $algo: tool not available to compute hash"
    RC=1
    return
  fi
  if [ "$(printf "%s" "$expected" | tr '[:upper:]' '[:lower:]')" = "$(printf "%s" "$got" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "[ OK ] $algo: $got"
  else
    echo "[FAIL] $algo: expected $expected got $got"
    RC=1
  fi
}

verify_algo sha256 "$M_SHA256"
verify_algo sha512 "$M_SHA512"
verify_algo blake3 "$M_BLAKE3"
verify_algo xxh128 "$M_XXH128"
verify_algo crc32 "$M_CRC32"

# per-entry verification
if [ -n "${ENTRY_ALGO:-}" ] && [ -n "${ENTRY_LINES_FILE:-}" ]; then
  echo
  echo "== Verifying per-entry hashes ($ENTRY_ALGO) =="
  TOTAL="$(wc -l < "$ENTRY_LINES_FILE" | awk '{print $1}')"
  OKCNT=0; FAILCNT=0; i=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    i=$((i+1))
    h="${line%%  *}"
    p="${line#*  }"
    info "  [$i/$TOTAL] $p ..."
    got="$(tar -xOf "$ARC_PATH" -- "$p" 2>/dev/null | pipe_hash "$ENTRY_ALGO")" || got=""
    if [ -z "$got" ]; then
      echo "[FAIL] $p : cannot compute $ENTRY_ALGO"
      FAILCNT=$((FAILCNT+1))
      RC=1
      continue
    fi
    if [ "$(printf "%s" "$h" | tr '[:upper:]' '[:lower:]')" = "$(printf "%s" "$got" | tr '[:upper:]' '[:lower:]')" ]; then
      OKCNT=$((OKCNT+1))
      if [ "$VERBOSE" -eq 1 ]; then
        echo "[ OK ] [$i/$TOTAL] $p"
      fi
    else
      echo "[FAIL] [$i/$TOTAL] $p : expected $h got $got"
      FAILCNT=$((FAILCNT+1))
      RC=1
    fi
  done < "$ENTRY_LINES_FILE"

  echo "Summary: total=$TOTAL ok=$OKCNT fail=$FAILCNT"
fi

# cleanup tmp
[ -n "${ENTRY_LINES_FILE:-}" ] && [ -f "$ENTRY_LINES_FILE" ] && rm -f "$ENTRY_LINES_FILE" || true

exit "$RC"
