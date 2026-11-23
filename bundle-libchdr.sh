#!/bin/sh
# Build the pinned decoder and embed it in a local BootInspector app.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ ! -f "$1/Contents/MacOS/BootInspector" ]; then
    echo 'Usage: sh bundle-libchdr.sh PATH/BootInspector.app [signing-identity]' >&2
    exit 2
fi

app=$1
identity=${2:--}
revision=47d794151b2b64f6aba60304e6480f4f5a2bc24b
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git -C "$scratch" init --quiet source
git -C "$scratch/source" fetch --quiet --depth=1 https://github.com/rtissera/libchdr.git "$revision"
git -C "$scratch/source" checkout --quiet --detach FETCH_HEAD
architectures=$(lipo -archs "$app/Contents/MacOS/BootInspector" | tr ' ' ';')
minimum=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$app/Contents/Info.plist" 2>/dev/null || true)
cmake -S "$scratch/source" -B "$scratch/build" -DCHDR_WANT_TESTS=OFF -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="$architectures" -DCMAKE_OSX_DEPLOYMENT_TARGET="$minimum"
cmake --build "$scratch/build" --config Release --target chdr

mkdir -p "$app/Contents/Frameworks" "$app/Contents/Resources/libchdr-licenses"
cp -L "$scratch/build/libchdr.dylib" "$app/Contents/Frameworks/libchdr.dylib"
cp "$scratch/source/LICENSE.txt" "$app/Contents/Resources/libchdr-licenses/libchdr.txt"
cp "$scratch/source/deps/lzma-26.02/LICENSE" "$app/Contents/Resources/libchdr-licenses/lzma.txt"
cp "$scratch/source/deps/miniz-3.1.2/miniz.h" "$app/Contents/Resources/libchdr-licenses/miniz.h"
curl -fsSL https://raw.githubusercontent.com/facebook/zstd/v1.5.7/LICENSE \
    -o "$app/Contents/Resources/libchdr-licenses/zstd.txt"
codesign -f -s "$identity" "$app/Contents/Frameworks/libchdr.dylib"
codesign -f -s "$identity" --preserve-metadata=entitlements,requirements,flags "$app"
codesign --verify --deep --strict "$app"
