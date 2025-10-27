# tar-manifest.sh — NAS 친화적 TAR 메니페스트 생성기 (POSIX sh)

- [다운로드](sandbox:/mnt/data/tar-manifest.sh)

## 빠른 사용
```sh
# 기본: .tar 옆에 .manifest.txt 작성
./tar-manifest.sh /mnt/nas/archive/foo.tar

# 목록 포함 + 멤버별 SHA-256
OUT_DIR=/mnt/nas/manifests ./tar-manifest.sh --list --entry-hash sha256 /mnt/nas/archive/foo.tar

# 여러 파일 병렬 처리
find /mnt/nas/archive -type f -name '*.tar' -print0 | xargs -0 -n1 -P4 ./tar-manifest.sh --list

# jq가 있으면 JSON으로 출력
FORMAT=json ./tar-manifest.sh --list /mnt/nas/archive/foo.tar
```
