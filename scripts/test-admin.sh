#!/usr/bin/env bash
set -Eeuo pipefail
binary=$1
data_dir=$(mktemp -d)
trap 'rm -rf -- "$data_dir"' EXIT
printf '123456' | "$binary" -init-admin -data "$data_dir"
[[ $("$binary" -admin-username -data "$data_dir") == admin ]]
printf '123456' | "$binary" -verify-admin -admin-user ' admin ' -data "$data_dir"
printf ' %s ' "\$ab!" | "$binary" -reset-admin -data "$data_dir"
printf ' %s ' "\$ab!" | "$binary" -verify-admin -admin-user admin -data "$data_dir"
if printf '123456' | "$binary" -verify-admin -admin-user admin -data "$data_dir" 2>/dev/null; then exit 1; fi
printf '654321' | "$binary" -reset-admin -admin-user renamed -data "$data_dir"
[[ $("$binary" -admin-username -data "$data_dir") == renamed ]]
printf '654321' | "$binary" -verify-admin -admin-user renamed -data "$data_dir"
if printf short | "$binary" -reset-admin -data "$data_dir" 2>/dev/null; then exit 1; fi
printf '654321' | "$binary" -verify-admin -admin-user renamed -data "$data_dir"
printf 'Administrator CLI bootstrap, login and reset checks passed.\n'
