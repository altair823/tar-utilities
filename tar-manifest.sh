#!/bin/sh
# tar-manifest.sh
# Create a rich, per-TAR manifest (single text file by default) with multiple checksums and metadata.
# Optional: include 'tar -tvf' listing and per-entry checksums (streamed).
#
# Requirements: POSIX sh + common CLI tools (tar, stat, date, awk, wc, uname, hostname).
# Optional tools auto-detected if present: sha256sum/sha512sum, openssl, b3sum, xxhsum, rhash, crc32, jq.
#
# Usage examples:
#   1) Basic: one manifest next to the .tar
#      ./tar-manifest.sh /mnt/nas/archive/foo.tar
#   2) Put manifests elsewhere, add full listing, and per-entry SHA-256
#      OUT_DIR=/mnt/nas/manifests ./tar-manifest.sh --list --entry-hash sha256 /mnt/nas/archive/foo.tar
#   3) Process many .tar files
#      find /mnt/nas/archive -type f -name '*.tar' -print0 | xargs -0 -n1 -P4 ./tar-manifest.sh --list
#   4) JSON output (requires jq). Will write *.manifest.json instead of .txt
#      FORMAT=json ./tar-manifest.sh --list /mnt/nas/archive/foo.tar
#
# Environment variables:
#   OUT_DIR=...        # directory to place manifest files (default: alongside the .tar)
#   FORMAT=txt|json    # default txt; json requires 'jq'
#   NOTES="..."        # free-form notes included in the manifest
#
# Flags:
#   --list                  include 'tar -tvf' listing in the manifest
#   --entry-hash <algo>     compute per-entry hash for files in tar (sha256|sha512|xxh128)
#   -v|--verbose            print progress for long operations (listing, hashing)
#   --help                  show help
#
set -eu

show_help() {
  sed -n '1,120p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------- helpers ----------

have() { command -v "$1" >/dev/null 2>&1; }

info() { if [ "${VERBOSE:-0}" -eq 1 ]; then printf "%s\n" "$*" >&2; fi; }

abs_path() {
  case "$1" in
    /*) printf "%s\n" "$1" ;;
    *)  printf "%s\n" "$(cd "$(dirname "$1")" 2>/dev/null && pwd)/$(basename "$1")" ;;
  esac
}

human_size() {
  b="$1"
  awk -v b="$b" 'function f(n){if(n<1024){printf "%.2f B",n;exit}n/=1024;if(n<1024){printf "%.2f KB",n;exit}n/=1024;if(n<1024){printf "%.2f MB",n;exit}n/=1024;if(n<1024){printf "%.2f GB",n;exit}n/=1024;if(n<1024){printf "%.2f TB",n;exit}n/=1024;printf "%.2f PB",n}
  BEGIN{f(b)}'
}

stat_field() {
  what="$1"; file="$2"
  case "$what" in
    size)
      if stat -c %s "$file" >/dev/null 2>&1; then stat -c %s "$file"
      elif stat -f %z "$file" >/dev/null 2>&1; then stat -f %z "$file"
      fi ;;
    mtime)
      if stat -c %Y "$file" >/dev/null 2>&1; then stat -c %Y "$file"
      elif stat -f %m "$file" >/dev/null 2>&1; then stat -f %m "$file"
      fi ;;
    ctime)
      if stat -c %Z "$file" >/dev/null 2>&1; then stat -c %Z "$file"
      elif stat -f %c "$file" >/dev/null 2>&1; then stat -f %c "$file"
      fi ;;
    inode)
      if stat -c %i "$file" >/dev/null 2>&1; then stat -c %i "$file"
      elif stat -f %i "$file" >/dev/null 2>&1; then stat -f %i "$file"
      fi ;;
    device)
      if stat -c %d "$file" >/dev/null 2>&1; then stat -c %d "$file"
      elif stat -f %d "$file" >/dev/null 2>&1; then stat -f %d "$file"
      fi ;;
  esac
}

iso_utc() {
  ts="$1"
  if have date && date -u -d "@0" "+%Y" >/dev/null 2>&1; then
    date -u -d "@$ts" "+%Y-%m-%dT%H:%M:%SZ"
  else
    date -u -r "$ts" "+%Y-%m-%dT%H:%M:%SZ"
  fi
}

guess_compressed() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    *.tar) echo "no" ;;
    *.tar.gz|*.tgz|*.tar.xz|*.txz|*.tar.zst|*.tzst|*.tar.bz2|*.tbz2|*.tar.lz4|*.tlz4|*.tar.z|*.taz) echo "yes" ;;
    *) echo "maybe" ;;
  esac
}

# hashers for whole-file
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

# per-stream hashing (for tar -xOf ...)
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

# ---------- parse args ----------
LIST=0
ENTRY_HASH=""
TAR_PATH=""
VERBOSE=0

while [ "$#" -gt 0 ]; do
  case "${1:-}" in
    --list) LIST=1 ;;
    --entry-hash) ENTRY_HASH="${2:-}"; shift ;;
    -v|--verbose) VERBOSE=1 ;;
    --help|-h) show_help; exit 0 ;;
    -*)
      echo "Unknown flag: $1" >&2; exit 2 ;;
    *)
      if [ -z "$TAR_PATH" ]; then TAR_PATH="$1"; else
        echo "Only one TAR path allowed." >&2; exit 2
      fi ;;
  esac
  shift
done

if [ -z "${TAR_PATH:-}" ]; then
  echo "Usage: $0 [--list] [--entry-hash sha256|sha512|xxh128] [-v] /path/to/archive.tar" >&2
  exit 2
fi

if [ ! -f "$TAR_PATH" ]; then
  echo "Not a file: $TAR_PATH" >&2
  exit 2
fi

FORMAT="${FORMAT:-txt}"
OUT_DIR="${OUT_DIR:-}"
NOTES="${NOTES:-}"

# ---------- gather file + host info ----------
APATH="$(abs_path "$TAR_PATH")"
ADIR="$(dirname "$APATH")"
ABASE="$(basename "$APATH")"

SIZE="$(stat_field size "$APATH" || echo "")"
MTIME="$(stat_field mtime "$APATH" || echo "")"
CTIME="$(stat_field ctime "$APATH" || echo "")"
INODE="$(stat_field inode "$APATH" || echo "")"
DEVICE="$(stat_field device "$APATH" || echo "")"

SIZE_HUMAN="$(human_size "${SIZE:-0}")"
MTIME_ISO="$( [ -n "$MTIME" ] && iso_utc "$MTIME" || echo "" )"
CTIME_ISO="$( [ -n "$CTIME" ] && iso_utc "$CTIME" || echo "" )"
CREATED_ISO="$(iso_utc "$(date +%s)")"

HOSTNAME="$(hostname 2>/dev/null || echo "")"
UNAME_P="$(uname -a 2>/dev/null || echo "")"
OS_SYS="$(uname -s 2>/dev/null || echo "")"
OS_REL="$(uname -r 2>/dev/null || echo "")"
OS_MCH="$(uname -m 2>/dev/null || echo "")"

IS_COMPRESSED="$(guess_compressed "$APATH")"

# ---------- checksums for archive ----------
info "Computing archive hashes for: $ABASE"
SHA256="$(hash_sha sha256 "$APATH")"; [ -n "$SHA256" ] && info "  sha256 ready"
SHA512="$(hash_sha sha512 "$APATH")"; [ -n "$SHA512" ] && info "  sha512 ready"
B3="$(hash_b3 "$APATH")";           [ -n "$B3"     ] && info "  blake3 ready"
XXH128="$(hash_xxh128 "$APATH")";   [ -n "$XXH128" ] && info "  xxh128 ready"
CRC32="$(hash_crc32 "$APATH")";     [ -n "$CRC32"  ] && info "  crc32  ready"

# ---------- optional listing ----------
LIST_FILE=""
MEMBERS_FILE="$(mktemp -t members.XXXXXX)"
info "Listing archive members..."
if tar -tf "$APATH" > "$MEMBERS_FILE" 2>/dev/null; then
  MEMBERS_CNT="$(wc -l < "$MEMBERS_FILE" | awk '{print $1}')"
  info "  members listed: $MEMBERS_CNT"
else
  MEMBERS_CNT="0"
  info "  (could not list members)"
fi

if [ "$LIST" -eq 1 ]; then
  LIST_FILE="$(mktemp -t tarlist.XXXXXX)"
  info "Creating detailed listing (tar -tvf)..."
  tar -tvf "$APATH" > "$LIST_FILE" 2>/dev/null || true
  info "  detailed listing done"
fi

# ---------- optional per-entry hashing ----------
ENTRY_FILE=""
if [ -n "$ENTRY_HASH" ]; then
  ENTRY_FILE="$(mktemp -t entryhash.XXXXXX)"
  FILES_TOTAL="$(awk '!/\/$/{print}' "$MEMBERS_FILE" | wc -l | awk "{print \$1}")"
  info "Hashing $FILES_TOTAL file entries using $ENTRY_HASH ..."
  i=0
  # We read from the members file to avoid re-scanning the archive twice.
  while IFS= read -r member; do
    case "$member" in
      */) continue ;;   # skip directories
    esac
    i=$((i+1))
    # stream the member; protect names that start with '-' via '--'
    h="$(tar -xOf "$APATH" -- "$member" 2>/dev/null | pipe_hash "$ENTRY_HASH")" || h=""
    if [ -n "$h" ]; then
      printf "%s  %s\n" "$h" "$member" >> "$ENTRY_FILE"
      info "  [$i/$FILES_TOTAL] $member  (done)"
    else
      info "  [$i/$FILES_TOTAL] $member  (skipped/unreadable)"
    fi
  done < "$MEMBERS_FILE"
  info "Per-entry hashing complete."
fi

# ---------- choose output path ----------
OUT_BASENAME="$ABASE.manifest"
if [ "$FORMAT" = "json" ]; then
  if ! have jq; then
    echo "FORMAT=json requires 'jq' to build JSON. Please install jq or use FORMAT=txt." >&2
    exit 3
  fi
  EXT="json"
else
  EXT="txt"
fi

if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR"
  OUT_PATH="$OUT_DIR/$OUT_BASENAME.$EXT"
else
  OUT_PATH="$ADIR/$OUT_BASENAME.$EXT"
fi

# ---------- write manifest ----------

if [ "$FORMAT" = "json" ]; then
  jq -n \
    --arg created_utc "$CREATED_ISO" \
    --arg tool "tar-manifest.sh" \
    --arg version "1.1.0" \
    --arg hostname "$HOSTNAME" \
    --arg platform "$UNAME_P" \
    --arg os_system "$OS_SYS" \
    --arg os_release "$OS_REL" \
    --arg os_machine "$OS_MCH" \
    --arg apath "$APATH" \
    --arg abase "$ABASE" \
    --arg adir "$ADIR" \
    --arg size_bytes "${SIZE:-}" \
    --arg size_human "$SIZE_HUMAN" \
    --arg mtime_utc "$MTIME_ISO" \
    --arg ctime_utc "$CTIME_ISO" \
    --arg inode "${INODE:-}" \
    --arg device "${DEVICE:-}" \
    --arg sha256 "$SHA256" \
    --arg sha512 "$SHA512" \
    --arg blake3 "$B3" \
    --arg xxh128 "$XXH128" \
    --arg crc32 "$CRC32" \
    --arg is_comp "$(guess_compressed "$APATH")" \
    --arg members_count "$MEMBERS_CNT" \
    --arg notes "$NOTES" \
    --arg list "$( [ -n "$LIST_FILE" ] && sed 's/\\/\\\\/g' "$LIST_FILE" | sed ':a;N;$!ba;s/\n/\\n/g' || echo "" )" \
    --arg entry_hash_algo "$ENTRY_HASH" \
    --arg entry_hashes "$( [ -n "$ENTRY_FILE" ] && sed 's/\\/\\\\/g' "$ENTRY_FILE" | sed ':a;N;$!ba;s/\n/\\n/g' || echo "" )" \
    '{
      schema_version: "1.1",
      created_utc: $created_utc,
      generator: { tool: $tool, version: $version },
      host: { hostname: $hostname, platform: $platform, os: { system: $os_system, release: $os_release, machine: $os_machine } },
      archive: {
        path: $apath, basename: $abase, dir: $adir,
        size_bytes: ($size_bytes|tonumber? // $size_bytes),
        size_human: $size_human,
        mtime_utc: $mtime_utc, ctime_utc: $ctime_utc,
        inode: ($inode|tonumber? // $inode), device: ($device|tonumber? // $device),
        hashes: { sha256: $sha256, sha512: $sha512, blake3: $blake3, xxh128: $xxh128, crc32: $crc32 }
      },
      tar: {
        is_compressed_guess: $is_comp,
        members_count: ($members_count|tonumber? // $members_count)
      },
      notes: $notes,
      listing_text: ( $list | select(length>0) ),
      per_entry_hash_algo: ( $entry_hash_algo | select(length>0) ),
      per_entry_hashes_text: ( $entry_hashes | select(length>0) )
    }' > "$OUT_PATH"
else
  {
    echo "# tar-manifest v1.1"
    echo "created_utc: $CREATED_ISO"
    echo
    echo "[host]"
    echo "hostname: $HOSTNAME"
    echo "platform: $UNAME_P"
    echo "os.system: $OS_SYS"
    echo "os.release: $OS_REL"
    echo "os.machine: $OS_MCH"
    echo
    echo "[archive]"
    echo "path: $APATH"
    echo "basename: $ABASE"
    echo "dir: $ADIR"
    echo "size_bytes: ${SIZE:-}"
    echo "size_human: $SIZE_HUMAN"
    echo "mtime_utc: $MTIME_ISO"
    echo "ctime_utc: $CTIME_ISO"
    echo "inode: ${INODE:-}"
    echo "device: ${DEVICE:-}"
    echo "hash.sha256: $SHA256"
    echo "hash.sha512: $SHA512"
    [ -n "$B3" ] && echo "hash.blake3: $B3"
    [ -n "$XXH128" ] && echo "hash.xxh128: $XXH128"
    [ -n "$CRC32" ] && echo "hash.crc32: $CRC32"
    echo
    echo "[tar]"
    echo "is_compressed_guess: $IS_COMPRESSED"
    echo "members_count: $MEMBERS_CNT"
    echo
    if [ -n "$NOTES" ]; then
      echo "[notes]"
      printf "%s\n" "$NOTES"
      echo
    fi
    if [ -n "$LIST_FILE" ] && [ -s "$LIST_FILE" ]; then
      echo "[tar.list]"
      cat "$LIST_FILE"
      echo
    fi
    if [ -n "$ENTRY_FILE" ] && [ -s "$ENTRY_FILE" ]; then
      echo "[tar.entry_hashes $ENTRY_HASH]"
      cat "$ENTRY_FILE"
      echo
    fi
  } > "$OUT_PATH"
fi

# cleanup temps
[ -f "$MEMBERS_FILE" ] && rm -f "$MEMBERS_FILE" || true
[ -n "${LIST_FILE:-}" ] && [ -f "$LIST_FILE" ] && rm -f "$LIST_FILE" || true
[ -n "${ENTRY_FILE:-}" ] && [ -f "$ENTRY_FILE" ] && rm -f "$ENTRY_FILE" || true

info "Manifest written: $OUT_PATH"
echo "Wrote manifest: $OUT_PATH"
exit 0
