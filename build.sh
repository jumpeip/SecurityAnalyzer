#!/usr/bin/env bash
# Build the SecurityAnalyzer Ghidra extension into an installable .zip.
#
# Compiles the plugin's Java sources against the jars in your Ghidra
# install, assembles the standard Ghidra extension zip layout, and
# drops the result in ./dist/.
#
# Usage:
#   ./build.sh [/path/to/ghidra_12.2_PUBLIC]
#
# Or set GHIDRA_INSTALL_DIR in the environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_INSTALL_DIR="${1:-${GHIDRA_INSTALL_DIR:-}}"

step()  { printf '\n==> %s\n' "$*"; }
fail()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------
step "Verifying Ghidra install"
[ -n "$GHIDRA_INSTALL_DIR" ] || fail "Pass /path/to/ghidra as arg 1, or set GHIDRA_INSTALL_DIR."
[ -d "$GHIDRA_INSTALL_DIR" ] || fail "Not a directory: $GHIDRA_INSTALL_DIR"
PROPS="$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
[ -f "$PROPS" ] || fail "Doesn't look like a Ghidra install root: $GHIDRA_INSTALL_DIR"

GHIDRA_VERSION=$(grep '^application.version=' "$PROPS" | cut -d= -f2- | tr -d '\r')
GHIDRA_RELNAME=$(grep '^application.release.name=' "$PROPS" | cut -d= -f2- | tr -d '\r')
: "${GHIDRA_VERSION:=UNKNOWN}"
: "${GHIDRA_RELNAME:=PUBLIC}"
echo "    Ghidra version: $GHIDRA_VERSION ($GHIDRA_RELNAME)"

# --------------------------------------------------------------------
step "Locating Java toolchain"
JAVAC="$(command -v javac || true)"
JAR="$(command -v jar || true)"

if [ -z "$JAVAC" ]; then
    for c in "$GHIDRA_INSTALL_DIR/support/jdk/bin/javac" "$GHIDRA_INSTALL_DIR/support/JDK/bin/javac"; do
        if [ -x "$c" ]; then
            JAVAC="$c"
            JAR="$(dirname "$c")/jar"
            break
        fi
    done
fi
[ -n "$JAVAC" ] && [ -x "$JAVAC" ] || fail "javac not found. Install JDK 21."
[ -n "$JAR"   ] && [ -x "$JAR"   ] || fail "jar not found alongside javac."
echo "    javac: $JAVAC"
echo "    jar:   $JAR"
"$JAVAC" -version 2>&1 | sed 's/^/    /'

# --------------------------------------------------------------------
step "Verifying source layout"
SRC_ROOT="$SCRIPT_DIR/src/main/java"
[ -d "$SRC_ROOT" ] || fail "Source root not found: $SRC_ROOT"
for req in extension.properties Module.manifest \
           src/main/java/securityanalyzer/SecurityAnalyzerPlugin.java \
           src/main/java/securityanalyzer/ui/SecurityAnalyzerProvider.java; do
    [ -f "$SCRIPT_DIR/$req" ] || fail "Missing required file: $req"
done

# --------------------------------------------------------------------
step "Collecting Ghidra jars for compile classpath"
JARS_FILE="$(mktemp)"
trap 'rm -f "$JARS_FILE"' EXIT
find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' \
    ! -name '*-src.jar' ! -name '*-javadoc.jar' > "$JARS_FILE"
JAR_COUNT=$(wc -l < "$JARS_FILE")
[ "$JAR_COUNT" -ge 5 ] || fail "Found only $JAR_COUNT jars under Ghidra/ — install incomplete."
echo "    $JAR_COUNT jars on classpath"

# Build classpath string with ':' separator (Linux/macOS)
CP="$(tr '\n' ':' < "$JARS_FILE" | sed 's/:$//')"

# --------------------------------------------------------------------
BUILD_DIR="$SCRIPT_DIR/build"
CLASS_DIR="$BUILD_DIR/classes"
DIST_DIR="$SCRIPT_DIR/dist"
STAGE_ROOT="$BUILD_DIR/stage/SecurityAnalyzer"

if [ "${CLEAN:-0}" = "1" ]; then
    step "Cleaning build/ and dist/"
    rm -rf "$BUILD_DIR" "$DIST_DIR"
fi
mkdir -p "$CLASS_DIR" "$DIST_DIR" "$STAGE_ROOT/lib"

# --------------------------------------------------------------------
step "Compiling"
SOURCES_FILE="$BUILD_DIR/sources.txt"
find "$SRC_ROOT" -name '*.java' > "$SOURCES_FILE"
SRC_COUNT=$(wc -l < "$SOURCES_FILE")
echo "    $SRC_COUNT source files"

"$JAVAC" -d "$CLASS_DIR" -cp "$CP" -encoding UTF-8 \
    -source 21 -target 21 -Xlint:none \
    @"$SOURCES_FILE"

CLASS_COUNT=$(find "$CLASS_DIR" -name '*.class' | wc -l)
echo "    $CLASS_COUNT .class files produced"

# --------------------------------------------------------------------
step "Packaging SecurityAnalyzer.jar"
JAR_PATH="$STAGE_ROOT/lib/SecurityAnalyzer.jar"
( cd "$CLASS_DIR" && "$JAR" cf "$JAR_PATH" . )
echo "    Wrote: $JAR_PATH ($(du -h "$JAR_PATH" | cut -f1))"

# --------------------------------------------------------------------
step "Assembling extension layout"
cp "$SCRIPT_DIR/extension.properties" "$STAGE_ROOT/"
cp "$SCRIPT_DIR/Module.manifest"      "$STAGE_ROOT/"
[ -f "$SCRIPT_DIR/README.md" ] && cp "$SCRIPT_DIR/README.md" "$STAGE_ROOT/"
[ -d "$SCRIPT_DIR/ghidra_scripts" ] && cp -r "$SCRIPT_DIR/ghidra_scripts" "$STAGE_ROOT/"
[ -d "$SCRIPT_DIR/data" ]           && cp -r "$SCRIPT_DIR/data"           "$STAGE_ROOT/"

# Stamp the version (Ghidra's installer requires this match the Ghidra version)
sed -i.bak "s/@extversion@/$GHIDRA_VERSION/g" "$STAGE_ROOT/extension.properties"
rm -f "$STAGE_ROOT/extension.properties.bak"
echo "    Stamped extension.properties with version=$GHIDRA_VERSION"

# --------------------------------------------------------------------
step "Creating distributable zip"
DATE=$(date +%Y%m%d)
ZIP_NAME="ghidra_${GHIDRA_VERSION}_${GHIDRA_RELNAME}_${DATE}_SecurityAnalyzer.zip"
ZIP_PATH="$DIST_DIR/$ZIP_NAME"
rm -f "$ZIP_PATH"
( cd "$BUILD_DIR/stage" && zip -rq "$ZIP_PATH" SecurityAnalyzer )

echo ""
echo "Done."
echo "    $ZIP_PATH ($(du -h "$ZIP_PATH" | cut -f1))"
echo ""
echo "Install:"
echo "  1. Open Ghidra (Project window)."
echo "  2. File -> Install Extensions -> '+' -> select the zip above."
echo "  3. Restart Ghidra."
echo "  4. Open a program in CodeBrowser."
echo "  5. File -> Configure -> Miscellaneous -> tick 'SecurityAnalyzer'."
echo "  6. Find the new menu under Tools -> Security Analyzer."
