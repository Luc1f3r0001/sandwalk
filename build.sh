#!/bin/bash
# Sandwalk build — single Go binary agent + bundled Kingfisher → .pkg
#
# Produces releases/Sandwalk-<version>.pkg.
set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-1.2.0}"
IDENTIFIER="com.sandwalk"
KINGFISHER_IDENTIFIER="com.sandwalk.kingfisher"
BUILD_DIR="$REPO_ROOT/build/pkg"
RELEASES_DIR="$REPO_ROOT/releases"
KINGFISHER_SRC="${KINGFISHER_SRC:-/opt/homebrew/bin/kingfisher}"

# ── Optional code-signing (env-driven) ────────────────────────────────────────
# Signing is OPTIONAL. Set SIGN_APP_IDENTITY to sign the binaries with a stable
# code-signing identity; leave it unset for an ad-hoc build (local install).
#   SIGN_APP_IDENTITY       identity name, e.g. "Sandwalk Code Signing"
#   SIGN_KEYCHAIN           keychain holding it
#   SIGN_KEYCHAIN_PASSWORD  optional; else read from ~/.sandwalk-signing/keychain-password
# For Gatekeeper on manual (non-MDM) installs you may also set:
#   SIGN_PKG_IDENTITY   Developer ID Installer identity to sign the .pkg
#   NOTARY_PROFILE      notarytool profile to notarize + staple
SIGN_APP_IDENTITY="${SIGN_APP_IDENTITY:-}"
SIGN_KEYCHAIN="${SIGN_KEYCHAIN:-$HOME/Library/Keychains/sandwalk-signing.keychain-db}"
SIGN_KEYCHAIN_PASSWORD="${SIGN_KEYCHAIN_PASSWORD:-}"
SIGN_PKG_IDENTITY="${SIGN_PKG_IDENTITY:-}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sandwalk build — version $VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Preflight
command -v go >/dev/null      || { echo "ERROR: go not found"; exit 1; }
command -v pkgbuild >/dev/null || { echo "ERROR: pkgbuild not found (Xcode CLT)"; exit 1; }
[ -x "$KINGFISHER_SRC" ]      || { echo "ERROR: kingfisher not found at $KINGFISHER_SRC (brew install kingfisher)"; exit 1; }

# ── Clean payload tree ────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/root/opt/sandwalk/bin"
mkdir -p "$BUILD_DIR/scripts"
mkdir -p "$RELEASES_DIR"

# ── 1. Compile the Go agent (native arm64, CGO for FSEvents) ──────────────────
echo "[1/4] Compiling Go agent..."
( cd "$REPO_ROOT/agent" && CGO_ENABLED=1 go build \
    -ldflags "-X main.version=$VERSION -s -w" \
    -o "$BUILD_DIR/root/opt/sandwalk/bin/sandwalk" ./cmd/sandwalk )
echo "      ✓ $(du -h "$BUILD_DIR/root/opt/sandwalk/bin/sandwalk" | cut -f1) binary"

# ── 2. Bundle Kingfisher ──────────────────────────────────────────────────────
echo "[2/4] Bundling Kingfisher..."
cp "$KINGFISHER_SRC" "$BUILD_DIR/root/opt/sandwalk/bin/kingfisher"
echo "      ✓ $("$KINGFISHER_SRC" --version 2>/dev/null | head -1)"

# ── 2.5 Optionally code-sign both binaries ────────────────────────────────────
SANDWALK_BIN="$BUILD_DIR/root/opt/sandwalk/bin/sandwalk"
KINGFISHER_BIN="$BUILD_DIR/root/opt/sandwalk/bin/kingfisher"
if [ -n "$SIGN_APP_IDENTITY" ]; then
    echo "[sign] Code-signing binaries as '$SIGN_APP_IDENTITY'..."
    KCARG=()
    if [ -n "$SIGN_KEYCHAIN" ] && [ -f "$SIGN_KEYCHAIN" ]; then
        KCARG=(--keychain "$SIGN_KEYCHAIN")
        KCPASS="$SIGN_KEYCHAIN_PASSWORD"
        [ -z "$KCPASS" ] && [ -f "$HOME/.sandwalk-signing/keychain-password" ] && KCPASS="$(cat "$HOME/.sandwalk-signing/keychain-password")"
        [ -n "$KCPASS" ] && security unlock-keychain -p "$KCPASS" "$SIGN_KEYCHAIN"
    fi
    codesign --force --sign "$SIGN_APP_IDENTITY" "${KCARG[@]}" -i "$KINGFISHER_IDENTIFIER" "$KINGFISHER_BIN"
    codesign --force --sign "$SIGN_APP_IDENTITY" "${KCARG[@]}" -i "$IDENTIFIER" "$SANDWALK_BIN"
    codesign --verify --strict "$SANDWALK_BIN" "$KINGFISHER_BIN"
    echo "      ✓ signed: $(codesign -dv "$SANDWALK_BIN" 2>&1 | grep -E 'Authority=|Identifier=' | tr '\n' ' ')"
else
    echo "[sign] SKIPPED — SIGN_APP_IDENTITY unset (ad-hoc build)"
fi

# ── 3. VERSION + plist + scripts ──────────────────────────────────────────────
echo "[3/4] Assembling payload..."
echo "$VERSION" > "$BUILD_DIR/root/opt/sandwalk/VERSION"
cp "$REPO_ROOT/setup/com.sandwalk.daemon.plist" "$BUILD_DIR/root/opt/sandwalk/"
# Inject the agent API key at build time — it is NOT committed to git. Provide it
# via the AGENT_KEY env var or ~/.sandwalk-signing/agent-key (0600, untracked).
AGENT_KEY="${AGENT_KEY:-$(cat "$HOME/.sandwalk-signing/agent-key" 2>/dev/null)}"
[ -n "$AGENT_KEY" ] || { echo "ERROR: AGENT_KEY not set (env or ~/.sandwalk-signing/agent-key)"; exit 1; }
sed -i '' "s|__AGENT_KEY__|$AGENT_KEY|" "$BUILD_DIR/root/opt/sandwalk/com.sandwalk.daemon.plist"
cp "$REPO_ROOT/setup/preinstall"  "$BUILD_DIR/scripts/preinstall"
cp "$REPO_ROOT/setup/postinstall" "$BUILD_DIR/scripts/postinstall"
chmod +x "$BUILD_DIR/scripts/preinstall" "$BUILD_DIR/scripts/postinstall"

# Optional: pin this install (disable self-update) so the release channel can't
# revert it. Used for local/test builds.
if [ "${DISABLE_AUTOUPDATE:-}" = "1" ]; then
    touch "$BUILD_DIR/root/opt/sandwalk/DISABLE_AUTOUPDATE"
    echo "      ⚠ auto-update DISABLED for this build (marker /opt/sandwalk/DISABLE_AUTOUPDATE)"
fi

# ── 4. Build the .pkg (signed with the Developer ID Installer cert if provided) ─
echo "[4/4] Building .pkg..."
PKG="$RELEASES_DIR/Sandwalk-$VERSION.pkg"
PKGBUILD_SIGN=()
[ -n "$SIGN_PKG_IDENTITY" ] && PKGBUILD_SIGN=(--sign "$SIGN_PKG_IDENTITY")
pkgbuild \
    --root        "$BUILD_DIR/root" \
    --scripts     "$BUILD_DIR/scripts" \
    --identifier  "$IDENTIFIER" \
    --version     "$VERSION" \
    --install-location "/" \
    "${PKGBUILD_SIGN[@]}" \
    "$PKG"

# ── 5. Notarize + staple (only if a notarytool profile is configured) ─────────
if [ -n "$NOTARY_PROFILE" ]; then
    echo "[notary] Submitting to Apple notary service (profile: $NOTARY_PROFILE)..."
    xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
    echo "      ✓ notarized + stapled"
else
    echo "[notary] SKIPPED — NOTARY_PROFILE unset (pkg not notarized)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ $PKG"
echo "  $(du -h "$PKG" | cut -f1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
