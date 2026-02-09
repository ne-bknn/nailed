// SPDX-License-Identifier: Apache-2.0
import Foundation
import CryptoKit
import X509
import Security
import SwiftASN1

public enum NailedCoreError: Error, LocalizedError {
    case identityNotFound
    case privateKeyNotFound
    case secureEnclaveUnavailable
    case accessControlFailed
    case invalidCertificateData(reason: String)
    case certificateAlreadyExists
    case keychainError(operation: String, status: OSStatus)
    case signingFailed(reason: String)
    case missingEntitlement
    
    public var errorDescription: String? {
        switch self {
        case .identityNotFound:
            return "No identity found in Secure Enclave"
        case .privateKeyNotFound:
            return "Private key not found in Secure Enclave"
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this device"
        case .accessControlFailed:
            return "Failed to create access control for Secure Enclave key"
        case .invalidCertificateData(let reason):
            return "Invalid certificate data: \(reason)"
        case .certificateAlreadyExists:
            return "Certificate already exists in the keychain"
        case .keychainError(let operation, let status):
            return "Keychain operation '\(operation)' failed with status \(status)"
        case .signingFailed(let reason):
            return "Signing failed: \(reason)"
        case .missingEntitlement:
            return "App is missing required entitlements"
        }
    }
    
    public var failureReason: String? {
        switch self {
        case .identityNotFound:
            return "No identity exists in the Secure Enclave."
        case .privateKeyNotFound:
            return "The private key is not available in the Secure Enclave."
        case .secureEnclaveUnavailable:
            return "The Secure Enclave hardware is not available on this Mac."
        case .accessControlFailed:
            return "Could not configure access control flags for the Secure Enclave key."
        case .invalidCertificateData:
            return "The provided certificate data is malformed or invalid."
        case .certificateAlreadyExists:
            return "This certificate is already imported in the keychain."
        case .keychainError:
            return "A keychain operation returned an unexpected error."
        case .signingFailed:
            return "The Secure Enclave key could not produce a signature."
        case .missingEntitlement:
            return "The app is missing required entitlements for Secure Enclave access."
        }
    }
}

// MARK: - Certificate Information
public struct CertificateInfo {
    public let commonName: String?
    public let issuerCommonName: String?
    public let notValidBefore: Date
    public let notValidAfter: Date
    public let isValid: Bool
    
    public init(commonName: String?, issuerCommonName: String?, notValidBefore: Date, notValidAfter: Date) {
        self.commonName = commonName
        self.issuerCommonName = issuerCommonName
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        
        let now = Date()
        self.isValid = now >= notValidBefore && now <= notValidAfter
    }
}

public struct NailedCore {
    private static let fixedTag = "com.nailed.single.identity"
    private let tag: String
    private let log = NailedLogger.shared
    // private let keychainAccessGroup: String
    
    public init() throws {
        self.tag = Self.fixedTag
        // self.keychainAccessGroup = "6RQQWGRA2K.com.ne-bknn.nailed"
    }
    
    // MARK: - Error Helpers
    
    /// Map a non-success OSStatus to the appropriate NailedCoreError
    private static func throwKeychainError(_ status: OSStatus, operation: String) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw NailedCoreError.certificateAlreadyExists
        case errSecMissingEntitlement:
            throw NailedCoreError.missingEntitlement
        default:
            throw NailedCoreError.keychainError(operation: operation, status: status)
        }
    }
    
    // MARK: - Secure Enclave Operations
    
    /// Check if Secure Enclave is available
    private func isSecureEnclaveAvailable() -> Bool {
        return SecureEnclave.isAvailable
    }
    
    /// Generate a new key pair in the Secure Enclave
    private func generateKey() throws -> SecKey {
        log.info("Generating new key pair in Secure Enclave", category: "core")
        // Check Secure Enclave availability
        guard isSecureEnclaveAvailable() else {
            log.error("Secure Enclave is not available", category: "core")
            throw NailedCoreError.secureEnclaveUnavailable
        }
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            nil
        ) else {
            throw NailedCoreError.accessControlFailed
        }

        let tagData = Data(tag.utf8)

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationLabel: tag,
            kSecAttrApplicationTag: tagData,
            kSecAttrLabel: tag,
            // kSecAttrAccessGroup: keychainAccessGroup,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrAccessControl: access,
                kSecAttrIsExtractable: false,
                // kSecAttrAccessGroup: keychainAccessGroup
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes, &error) else {
            if let cfError = error?.takeRetainedValue() {
                let nsError = cfError as Error as NSError
                log.error("SecKeyCreateRandomKey failed (code \(nsError.code)): \(nsError.localizedDescription)", category: "core")
                if nsError.code == -34018 { // errSecMissingEntitlement
                    throw NailedCoreError.missingEntitlement
                }
                throw NailedCoreError.keychainError(
                    operation: "generate key",
                    status: OSStatus(nsError.code)
                )
            }
            throw NailedCoreError.keychainError(operation: "generate key", status: errSecInternalError)
        }

        log.info("Key pair generated successfully", category: "core")
        return key
    }
    
    /// Get the private key from the Secure Enclave
    private func getPrivateKey() throws -> SecKey? {
        let tagData = Data(tag.utf8)

        let query: [String: Any] = [
            kSecClass              as String: kSecClassKey,
            kSecAttrKeyClass       as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType        as String: kSecAttrKeyTypeECSECPrimeRandom,
            // kSecAttrAccessGroup    as String: keychainAccessGroup,
            kSecReturnRef          as String: kCFBooleanTrue
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            try Self.throwKeychainError(status, operation: "retrieve private key")
            return nil // unreachable, throwKeychainError always throws for non-success
        }
    }
    
    /// Generate a Certificate Signing Request using swift-certificates
    private func generateCSR(privateKey: SecKey, commonName: String) throws -> CertificateSigningRequest {
        let subject = try DistinguishedName([
            .init(type: .NameAttributes.commonName, utf8String: commonName),
        ])
        
        // Create a custom private key wrapper that uses the Secure Enclave key for signing
        let secureEnclavePrivateKey = try Certificate.PrivateKey(privateKey)
        
        let extensions = try Certificate.Extensions {}
        let extensionRequest = ExtensionRequest(extensions: extensions)
        let attributes = try CertificateSigningRequest.Attributes(
            [.init(extensionRequest)]
        )

        return try CertificateSigningRequest(version: .v1,
                                             subject: subject,
                                             privateKey: secureEnclavePrivateKey,
                                             attributes: attributes,
                                             signatureAlgorithm: .ecdsaWithSHA256
        )
    }
    
    /// Import a certificate into the keychain
    private func importCertificate(_ certificate: SecCertificate) throws {
        log.info("Importing certificate into keychain", category: "core")
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            // kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecValueRef as String: certificate
        ]

        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            log.error("Certificate import failed with OSStatus \(status)", category: "core")
            try Self.throwKeychainError(status, operation: "import certificate")
            return // unreachable
        }
        log.info("Certificate imported successfully", category: "core")
    }
    
    /// Sign data using the private key
    private func sign(digest: Data, privateKey: SecKey) throws -> Data {
        precondition(digest.count == 32, "OpenVPN always supplies a 32-byte digest")
        log.debug("Signing \(digest.count)-byte digest", category: "core")
        
        let alg = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, alg) else {
            log.error("Key does not support ECDSA-SHA256 digest signing", category: "core")
            throw NailedCoreError.signingFailed(reason: "Key does not support ECDSA-SHA256 digest signing")
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, alg, digest as CFData, &error) as Data? else {
            if let cfError = error?.takeRetainedValue() {
                let nsError = cfError as Error as NSError
                log.error("SecKeyCreateSignature failed (status \(nsError.code)): \(nsError.localizedDescription)", category: "core")
                throw NailedCoreError.signingFailed(
                    reason: "SecKeyCreateSignature failed (status \(nsError.code)): \(nsError.localizedDescription)"
                )
            }
            throw NailedCoreError.signingFailed(reason: "SecKeyCreateSignature returned nil")
        }

        log.debug("Signature produced: \(signature.count) bytes", category: "core")
        return signature
    }
    
    /// Export the certificate matching the given private key
    private func exportCertificate(matching key: SecKey) -> Data? {
        guard
            let keyAttrs = SecKeyCopyAttributes(key) as? [CFString: Any],
            let pubKeyHash = keyAttrs[kSecAttrApplicationLabel] as? Data
        else { return nil }
        
        // Ask the keychain for a certificate whose public key hash equals that hash
        let query: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrPublicKeyHash: pubKeyHash,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnRef: kCFBooleanTrue
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        let sc = result as! SecCertificate
        return SecCertificateCopyData(sc) as Data
    }
    
    /// Export the public key for the given private key
    private func exportPublicKey(privateKey: SecKey) throws -> Data? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        return pubKeyData
    }
    
    /// Delete identity (key + certificates) from the keychain
    public func deleteIdentity() throws {
        log.info("Deleting identity from keychain", category: "core")
        let tagData = Data(tag.utf8)

        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            // kSecAttrAccessGroup as String: keychainAccessGroup
        ]

        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tagData,
            // kSecAttrAccessGroup as String: keychainAccessGroup
        ]

        SecItemDelete(keyQuery as CFDictionary)
        SecItemDelete(certQuery as CFDictionary)
        log.info("Identity deleted", category: "core")
    }
    
    // MARK: - Public Interface
    
    /// Check if an identity exists in the Secure Enclave
    public func hasIdentity() throws -> Bool {
        return try getPrivateKey() != nil
    }
    
    /// Generate the single identity with a secure enclave key pair
    public func generateIdentity() throws {
        log.info("Generating new identity", category: "core")
        // Delete any existing identity first
        try? deleteIdentity()
        _ = try generateKey()
    }
    
    /// Import a certificate for the identity
    public func importCertificate(certificateData: Data) throws {
        log.info("Importing certificate (\(certificateData.count) bytes)", category: "core")
        guard try hasIdentity() else {
            log.error("Cannot import certificate: no identity found", category: "core")
            throw NailedCoreError.identityNotFound
        }
        
        // Convert certificate data to SecCertificate
        guard let secCertificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            log.error("Invalid certificate data: unable to create SecCertificate", category: "core")
            throw NailedCoreError.invalidCertificateData(
                reason: "Unable to create SecCertificate from provided data"
            )
        }
        
        try importCertificate(secCertificate)
    }
    
    /// Check if the identity has a certificate
    public func hasCertificate() throws -> Bool {
        guard try hasIdentity() else {
            return false
        }
        
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        return exportCertificate(matching: privateKey) != nil
    }
    
    /// Generate a Certificate Signing Request for the identity
    public func generateCSR(commonName: String) throws -> Data {
        log.info("Generating CSR for CN=\(commonName)", category: "core")
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        let csr = try generateCSR(privateKey: privateKey, commonName: commonName)
        
        var serializer = DER.Serializer()
        try csr.serialize(into: &serializer)
        log.info("CSR generated successfully", category: "core")
        return Data(serializer.serializedBytes)
    }
    
    /// Sign data using the identity's private key
    public func sign(data: Data) throws -> Data {
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        return try sign(digest: data, privateKey: privateKey)
    }
    
    // Get certificate information for the identity
    public func getCertificateInfo() throws -> CertificateInfo? {
        guard try hasIdentity() else {
            return nil
        }
        
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        // Try to export the certificate data
        guard let certificateData = exportCertificate(matching: privateKey) else {
            return nil
        }
        
        // Parse the certificate using X509
        do {
            let certificate = try Certificate(derEncoded: Array(certificateData))
            
            // Extract common name from subject
            let subjectCommonName = certificate.subject.first { rdn in
                rdn.first?.type == .NameAttributes.commonName
            }?.first?.value.description
            
            // Extract common name from issuer
            let issuerCommonName = certificate.issuer.first { rdn in
                rdn.first?.type == .NameAttributes.commonName
            }?.first?.value.description
            
            return CertificateInfo(
                commonName: subjectCommonName,
                issuerCommonName: issuerCommonName,
                notValidBefore: certificate.notValidBefore,
                notValidAfter: certificate.notValidAfter
            )
        } catch {
            log.error("Failed to parse certificate: \(error.localizedDescription)", category: "core")
            throw NailedCoreError.invalidCertificateData(
                reason: "Failed to parse certificate: \(error.localizedDescription)"
            )
        }
    }
    
    /// Export certificate for the identity (convenience method)
    public func exportCertificate() throws -> Data? {
        guard try hasIdentity() else {
            return nil
        }
        
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        return exportCertificate(matching: privateKey)
    }
    
    /// Export public key for the identity (convenience method)
    public func exportPublicKey() throws -> Data? {
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        return try exportPublicKey(privateKey: privateKey)
    }
    
    // MARK: - PEM Utilities
    
    /// Parse certificate data from PEM or DER format, returning DER bytes
    public static func parseCertificateData(from fileData: Data) -> Data {
        if let pemString = String(data: fileData, encoding: .utf8) {
            let cleaned = pemString
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
                .replacingOccurrences(of: " ", with: "")
            
            if let decoded = Data(base64Encoded: cleaned) {
                return decoded
            }
        }
        return fileData
    }
    
    /// Convert DER data to PEM string with the given label (e.g. "CERTIFICATE", "CERTIFICATE REQUEST")
    public static func derToPEM(_ data: Data, label: String) -> String {
        let base64 = data.base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: 64).map { offset -> String in
            let start = base64.index(base64.startIndex, offsetBy: offset)
            let end = base64.index(start, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            return String(base64[start..<end])
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }
}
