# tar-verify.sh — TAR 메니페스트 검증기 (POSIX sh)

- [다운로드](sandbox:/mnt/data/tar-verify.sh)

## 사용법
```sh
# 기본: 메니페스트와 기록된 TAR 경로 기준으로 검증
./tar-verify.sh /mnt/nas/manifests/foo.tar.manifest.txt

# JSON 메니페스트(jq 필요)
./tar-verify.sh /mnt/nas/manifests/foo.tar.manifest.json

# 메니페스트 안의 TAR 경로 대신, 현재 실제 경로를 지정 (이동/마이그레이션했을 때 유용)
./tar-verify.sh --tar /mnt/nas/archive/foo.tar /mnt/nas/manifests/foo.tar.manifest.txt

# 멤버별 해시 결과를 상세 출력
./tar-verify.sh -v /mnt/nas/manifests/foo.tar.manifest.txt
```

## 검증 항목
- **아카이브 자체**: size, sha256/sha512/blake3/xxh128/crc32 (메니페스트에 있는 항목만)
- **멤버별 검증**: 메니페스트에 `[tar.entry_hashes <algo>]`(TXT) 또는 `per_entry_hash_algo`/`per_entry_hashes_text`(JSON)가 있으면
  각 멤버를 `tar -xOf`로 스트리밍해 해시를 계산해 대조

## 필요한 도구
- 기본: `tar`, `stat`, `awk`, `wc`, `date` (일반 NAS/리눅스에 기본 포함)
- 해시: `sha256sum`/`sha512sum` 또는 `openssl`, 있으면 `rhash`/`xxhsum`/`b3sum`/`crc32`
- JSON 파싱: `jq` (JSON 메니페스트 때만 필요)
