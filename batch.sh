#! /bin/sh

for i in $(ls); do tar -cf - "$i" | pv > "$i.tar" ; done && for i in $(ls -- *.tar); do sh /mnt/hs-nas-zfs/altairBackup/archive/lto-utilities/tar-manifest.sh --list --entry-hash sha256 $i; done
