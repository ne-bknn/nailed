# Code Signing Setup for GitHub Actions

This guide explains how to set up code signing for the nailed macOS app in GitHub Actions.

## Prerequisites

1. **Apple Developer Account** with macOS App Development capability
2. **Development Team ID** (found in Apple Developer portal)
3. **Distribution Certificate** (Developer ID Application or Mac App Distribution)
4. **Provisioning Profile** (if required for your app)

## Step 1: Export Your Signing Certificate

### From Keychain Access:
1. Open **Keychain Access** on your Mac
2. Find your **Developer ID Application** or **Mac App Distribution** certificate
3. Right-click and select **Export**
4. Choose **Personal Information Exchange (.p12)** format
5. Set a password (you'll need this for the secret)
6. Save the file

### From Command Line:
```bash
# Export certificate to p12 format
security export -k login.keychain -t identities -f pkcs12 -o certificate.p12 "Developer ID Application: Your Name (TEAM_ID)"
```

## Step 2: Convert Certificate to Base64

```bash
# Convert p12 to base64 for GitHub secret
base64 -i certificate.p12 | pbcopy
```

## Step 3: Set Up GitHub Secrets

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions** and add these secrets:

### Required Secrets:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `MACOS_CERTIFICATE` | Base64-encoded p12 certificate | `MIIF...` (long base64 string) |
| `MACOS_CERTIFICATE_PASSWORD` | Password for the p12 certificate | `your-p12-password` |
| `DEVELOPMENT_TEAM` | Your Apple Developer Team ID | `6RQQWGRA2K` |
| `CODE_SIGN_IDENTITY` | Full certificate name | `Developer ID Application: Your Name (6RQQWGRA2K)` |
| `PROVISIONING_PROFILE_SPECIFIER` | Provisioning profile name (if needed) | `nailed_App_Store` |
| `NOTARY_APPLE_ID` | Apple ID email used for notarization | `you@example.com` |
| `NOTARY_TEAM_ID` | Apple Developer Team ID for notarization | `6RQQWGRA2K` |
| `NOTARY_APP_PASSWORD` | App-specific password for notarization | `xxxx-xxxx-xxxx-xxxx` |

### Optional Secrets:

| Secret Name | Description | When Needed |
|-------------|-------------|-------------|
| `APP_STORE_CONNECT_API_KEY` | App Store Connect API key | For App Store distribution |
| `APP_STORE_CONNECT_ISSUER_ID` | App Store Connect issuer ID | For App Store distribution |
| `APP_STORE_CONNECT_KEY_ID` | App Store Connect key ID | For App Store distribution |

## Step 4: Verify Your Setup

### Check Certificate Details:
```bash
# View certificate details
security find-identity -v -p codesigning
```

### Test Local Signing:
```bash
# Test signing a file
codesign --sign "Developer ID Application: Your Name (TEAM_ID)" --force --deep /path/to/your/app.app
```

## Security Best Practices

### 1. **Rotate Certificates Regularly**
- Apple certificates expire annually
- Set calendar reminders to renew before expiration
- Update GitHub secrets when renewing

### 2. **Use Least Privilege**
- Only grant necessary capabilities to certificates
- Use separate certificates for development vs distribution

### 3. **Secure Secret Storage**
- Never commit certificates to version control
- Use GitHub's encrypted secrets
- Consider using GitHub's OIDC for enhanced security

### 4. **Monitor Signing**
- Check signing logs in GitHub Actions
- Verify signed artifacts with `codesign -dv`

## Troubleshooting

### Common Issues:

#### "Certificate not found"
- Verify the certificate name in `CODE_SIGN_IDENTITY` secret
- Check that the certificate is in the correct keychain

#### "Invalid certificate"
- Ensure the p12 file is properly base64 encoded
- Verify the password matches the p12 file

#### "Provisioning profile not found"
- Check that the provisioning profile name is correct
- Ensure the profile is compatible with your certificate

#### "Team ID mismatch"
- Verify `DEVELOPMENT_TEAM` matches your Apple Developer Team ID
- Check that the certificate belongs to the correct team

### Debug Commands:

```bash
# Check available certificates
security find-identity -v -p codesigning

# Verify app signing
codesign -dv --verbose=4 /path/to/app.app

# Check provisioning profiles
ls ~/Library/MobileDevice/Provisioning\ Profiles/

# Test keychain access
security list-keychains
```

## Alternative: Automatic Signing

If you prefer automatic signing (simpler but less control):

1. Remove the "Setup code signing" step
2. Use these build parameters instead:
   ```bash
   DEVELOPMENT_TEAM="${{ secrets.DEVELOPMENT_TEAM }}" \
   CODE_SIGN_STYLE="Automatic" \
   CODE_SIGN_IDENTITY="Apple Development"
   ```

## Next Steps

1. Set up the secrets in your GitHub repository
2. Push a commit to open a PR to see CI (lint, tests, CodeQL)
3. Merge to `master` or wait for nightly to get signed DMG artifact
4. Push a tag like `v1.0.0` to trigger notarized release creation
5. Verify the signed, stapled DMG works correctly

## Resources

- [Apple Developer Documentation](https://developer.apple.com/support/code-signing/)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Code Signing Best Practices](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html) 