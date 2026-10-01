#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 || "$1" != *.dext ]]; then
    echo "Usage: $0 /path/to/YourBundle.Driver.dext" >&2
    exit 2
fi

driver_dir=$(cd "$(dirname "$0")" && pwd)
shared_dir="$driver_dir/../Shared"
destination="$1"
team_id="${ALFA_TEAM_ID:-UNCONFIGURED}"
host_id="${ALFA_HOST_BUNDLE_ID:-io.github.clucas.AlfaWiFi}"
driver_id="${host_id}.Driver"
if [[ "$team_id" != UNCONFIGURED && ! "$team_id" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "ALFA_TEAM_ID must contain ten uppercase letters or digits, or UNCONFIGURED for inspection." >&2
    exit 2
fi
if [[ ! "$host_id" =~ ^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$ ]]; then
    echo "ALFA_HOST_BUNDLE_ID must be a reverse-DNS bundle identifier." >&2
    exit 2
fi
sdk=$(xcrun --sdk driverkit --show-sdk-path)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/alfa-dext.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT

compiler=(xcrun --sdk driverkit clang++ -target arm64-apple-driverkit24.0
    -isysroot "$sdk" -std=c++17 -fno-exceptions -fno-rtti -fblocks
    -I "$build_dir" -I "$shared_dir" -I "$driver_dir"
    "-DALFA_TEAM_IDENTIFIER=\"${team_id}\""
    "-DALFA_HOST_APPLICATION_IDENTIFIER=\"${team_id}.${host_id}\"")
objects=()
for class in AlfaEthernetDriver AlfaControlService AlfaEthernetUserClient; do
    xcrun --sdk driverkit iig --def "$driver_dir/$class.iig" \
        --header "$build_dir/$class.h" --impl "$build_dir/$class.iig.cpp" \
        --deployment-target 24.0 -- -D__IIG=1 -isysroot "$sdk" \
        -I "$shared_dir" -I "$driver_dir" -x c++ -std=c++17
done
for class in AlfaEthernetDriver AlfaControlService AlfaEthernetUserClient; do
    "${compiler[@]}" -c "$driver_dir/$class.cpp" -o "$build_dir/$class.o"
    "${compiler[@]}" -c "$build_dir/$class.iig.cpp" -o "$build_dir/$class.iig.o"
    objects+=("$build_dir/$class.o" "$build_dir/$class.iig.o")
done
"${compiler[@]}" "${objects[@]}" -framework DriverKit -framework NetworkingDriverKit \
    -o "$build_dir/AlfaEthernetDriver"
mkdir -p "$destination"
cp "$build_dir/AlfaEthernetDriver" "$destination/AlfaEthernetDriver"
cp "$driver_dir/Info.plist" "$destination/Info.plist"
plutil -replace CFBundleIdentifier -string "$driver_id" "$destination/Info.plist"
for key in CFBundleIdentifier IOMatchCategory IOUserServerName; do
    plutil -replace "IOKitPersonalities.AlfaEthernetDriver.$key" -string "$driver_id" "$destination/Info.plist"
done
cp "$driver_dir/LICENSE.apple.txt" "$destination/LICENSE.apple.txt"
plutil -lint "$destination/Info.plist"
echo "Built unsigned DriverKit bundle: $destination"
