#!/bin/bash
# Build the nailed installer package
# Usage: ./scripts/build-pkg.sh <app_path> <dylib_path> <output_pkg> <signing_identity> <version>

set -e

APP_PATH="$1"
DYLIB_PATH="$2"
OUTPUT_PKG="$3"
SIGNING_IDENTITY="$4"
VERSION="${5:-1.0.0}"

if [ -z "$APP_PATH" ] || [ -z "$DYLIB_PATH" ] || [ -z "$OUTPUT_PKG" ]; then
    echo "Usage: $0 <app_path> <dylib_path> <output_pkg> [signing_identity] [version]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(mktemp -d)"
PKG_ROOT="$BUILD_DIR/root"
SCRIPTS_DIR="$BUILD_DIR/scripts"
COMPONENT_PKGS="$BUILD_DIR/components"

echo "Building nailed installer package..."
echo "  App: $APP_PATH"
echo "  Dylib: $DYLIB_PATH"
echo "  Output: $OUTPUT_PKG"
echo "  Version: $VERSION"

# Create directory structure
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$PKG_ROOT/Library/Application Support/nailed"
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$COMPONENT_PKGS"

# Copy the app
echo "Copying application..."
cp -R "$APP_PATH" "$PKG_ROOT/Applications/"

# Copy the dylib to a system location (postinstall will copy to user home)
echo "Copying dylib..."
cp "$DYLIB_PATH" "$PKG_ROOT/Library/Application Support/nailed/"

# Copy postinstall script
cp "$SCRIPT_DIR/postinstall" "$SCRIPTS_DIR/"
chmod +x "$SCRIPTS_DIR/postinstall"

# Build the component package
echo "Building component package..."
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "com.ne-bknn.nailed.pkg" \
    --version "$VERSION" \
    --install-location "/" \
    "$COMPONENT_PKGS/nailed-component.pkg"

# Create distribution XML
cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>nailed</title>
    <organization>com.ne-bknn.nailed</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    
    <welcome file="welcome.html" mime-type="text/html"/>
    <conclusion file="conclusion.html" mime-type="text/html"/>
    
    <choices-outline>
        <line choice="default">
            <line choice="com.ne-bknn.nailed.pkg"/>
        </line>
    </choices-outline>
    
    <choice id="default"/>
    <choice id="com.ne-bknn.nailed.pkg" visible="false">
        <pkg-ref id="com.ne-bknn.nailed.pkg"/>
    </choice>
    
    <pkg-ref id="com.ne-bknn.nailed.pkg" version="$VERSION" onConclusion="none">nailed-component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create welcome HTML
mkdir -p "$BUILD_DIR/resources"
cat > "$BUILD_DIR/resources/welcome.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 20px;
            line-height: 1.6;
        }
        h1 { margin-bottom: 20px; }
        ul {
            list-style: none;
            padding: 0;
            margin: 20px 0;
        }
        li {
            padding: 8px 0;
        }
        code { 
            font-family: "SF Mono", Menlo, Monaco, monospace;
        }
    </style>
</head>
<body>
    <h1>Welcome to nailed</h1>
    <p>This installer will install:</p>
    <ul>
        <li><strong>nailed.app</strong> → <code>/Applications</code></li>
        <li><strong>libnailed_pkcs11.dylib</strong> → <code>~/.pkcs11_modules</code></li>
    </ul>
</body>
</html>
EOF

cat > "$BUILD_DIR/resources/conclusion.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 20px;
            line-height: 1.6;
        }
        h1 { margin-bottom: 20px; }
        ol {
            padding-left: 20px;
            margin: 20px 0;
        }
        li {
            padding: 6px 0;
        }
        code { 
            font-family: "SF Mono", Menlo, Monaco, monospace;
        }
    </style>
</head>
<body>
    <h1>Installation Complete</h1>
    <p>nailed has been successfully installed.</p>
    <p><strong>Next steps:</strong></p>
    <ol>
        <li>Open <strong>nailed</strong> from your Applications folder</li>
        <li>Create or import your Secure Enclave identity</li>
        <li>Configure your applications to use the PKCS#11 module at:<br>
            <code>~/.pkcs11_modules/libnailed_pkcs11.dylib</code></li>
    </ol>
</body>
</html>
EOF

# Build the product archive (distribution package)
echo "Building distribution package..."
productbuild \
    --distribution "$BUILD_DIR/distribution.xml" \
    --resources "$BUILD_DIR/resources" \
    --package-path "$COMPONENT_PKGS" \
    "$BUILD_DIR/nailed-unsigned.pkg"

# Sign the package if identity provided
if [ -n "$SIGNING_IDENTITY" ]; then
    echo "Signing package with identity: $SIGNING_IDENTITY"
    productsign \
        --sign "$SIGNING_IDENTITY" \
        "$BUILD_DIR/nailed-unsigned.pkg" \
        "$OUTPUT_PKG"
else
    echo "No signing identity provided, package will be unsigned"
    cp "$BUILD_DIR/nailed-unsigned.pkg" "$OUTPUT_PKG"
fi

# Cleanup
rm -rf "$BUILD_DIR"

echo "Package created: $OUTPUT_PKG"

