#!/usr/bin/env bash
set -euo pipefail

test "$#" -eq 1 || { echo "Usage: bash scripts/build-webrtc.sh /absolute/native-build-directory" >&2; exit 1; }
build_root="$1"
case "$build_root" in
	/*) ;;
	*) echo "Build directory must be absolute" >&2; exit 1 ;;
esac
for tool in php phpize php-config g++ cmake git make pkg-config; do
	command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
pkg-config --exists openssl || { echo "OpenSSL development headers are missing" >&2; exit 1; }
test "$(php-config --version)" = "$(php -r 'echo PHP_VERSION;')" ||
	{ echo "PHP runtime and php-config versions differ; refusing ABI guess" >&2; exit 1; }
mkdir -p "$build_root"
build_root="$(cd "$build_root" && pwd -P)"
prefix="$build_root/install"
ext_commit=6ef8c2342e2638a05c46fd62e7e1bcefd3ce6ed8
datachannel_commit=443f6934d9007eb7076ab7825ba330f355fcbead

if test ! -d "$build_root/libdatachannel"; then
	git clone --depth=1 --recursive --branch v0.24.5 \
		https://github.com/paullouisageneau/libdatachannel.git "$build_root/libdatachannel"
fi
test "$(git -C "$build_root/libdatachannel" rev-parse HEAD)" = "$datachannel_commit"
git -C "$build_root/libdatachannel" diff --exit-code
git -C "$build_root/libdatachannel" submodule update --init --recursive
cmake -S "$build_root/libdatachannel" -B "$build_root/libdatachannel/build" \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
	-DBUILD_SHARED_LIBS=ON -DNO_EXAMPLES=ON -DNO_TESTS=ON -DNO_MEDIA=ON
cmake --build "$build_root/libdatachannel/build" --parallel 2
cmake --install "$build_root/libdatachannel/build"

if test ! -d "$build_root/ext-webrtc"; then
	git init "$build_root/ext-webrtc"
	git -C "$build_root/ext-webrtc" remote add origin https://github.com/axolotl-pm/ext-webrtc.git
	git -C "$build_root/ext-webrtc" fetch --depth=1 origin "$ext_commit"
	git -C "$build_root/ext-webrtc" checkout --detach FETCH_HEAD
fi
test "$(git -C "$build_root/ext-webrtc" rev-parse HEAD)" = "$ext_commit"
git -C "$build_root/ext-webrtc" diff --exit-code
(
	cd "$build_root/ext-webrtc"
	phpize
	./configure --enable-webrtc --with-libdatachannel="$prefix"
	make -j2
	php -d "extension=$build_root/ext-webrtc/modules/webrtc.so" --ri webrtc
	php -d "extension=$build_root/ext-webrtc/modules/webrtc.so" -r \
		'if(!extension_loaded("webrtc") || phpversion("webrtc") !== "0.3.0" || constant("pmmp\\webrtc\\WEBRTC_VERSION") !== "0.24.5"){exit(1);}'
	NO_INTERACTION=1 REPORT_EXIT_STATUS=1 TEST_PHP_EXECUTABLE="$(command -v php)" make test
)

mkdir -p "$build_root/ini"
printf 'extension=%s/ext-webrtc/modules/webrtc.so\n' "$build_root" > "$build_root/ini/webrtc.ini"
echo "Native build verified. Append $build_root/ini to PHP_INI_SCAN_DIR to enable it."
