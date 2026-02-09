// SPDX-License-Identifier: Apache-2.0
import Foundation
import CryptoKit
import X509
import Security
import SwiftASN1

public enum NailedCoreError: Error, LocalizedError {
    case identityNotFound
    case privateKeyNotFound
    case invalidCertificateData(reason: String)
    case enclaveOperationFailed(operation: String, underlyingError: Error)
    case missingEntitlement
    
    public var errorDescription: String? {
        switch self {
        case .identityNotFound:
            return "No identity found in Secure Enclave"
        case .privateKeyNotFound:
            return "Private key not found in Secure Enclave"
        case .invalidCertificateData(let reason):
            return "Invalid certificate data: \(reason)"
        case .enclaveOperationFailed(let operation, let error):
            return "Enclave operation '\(operation)' failed: \(error.localizedDescription)"
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
        case .invalidCertificateData:
            return "The provided certificate data is malformed or invalid."
        case .enclaveOperationFailed:
            return "A Secure Enclave operation failed."
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
    // private let keychainAccessGroup: String
    
    public init() throws {
        self.tag = Self.fixedTag
        // self.keychainAccessGroup = "6RQQWGRA2K.com.ne-bknn.nailed"
    }
    
    // MARK: - Secure Enclave Operations
    
    /// Check if Secure Enclave is available
    private func isSecureEnclaveAvailable() -> Bool {
        return SecureEnclave.isAvailable
    }
    
    /// Generate a new key pair in the Secure Enclave
    private func generateKey() throws -> SecKey {
        // Check Secure Enclave availability
        guard isSecureEnclaveAvailable() else {
            throw NSError(domain: "SecureEnclaveError",
                         code: -1,
                         userInfo: [NSLocalizedDescriptionKey: "Secure Enclave is not available on this device"])
        }
        
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            nil
        ) else {
            throw NSError(domain: "SecureEnclaveError",
                          code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to create access control"])
        }

        guard let tagData = tag.data(using: .utf8) else {
            throw NSError(domain: "SecureEnclaveError",
                          code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to encode tag data"])
        }

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
            let underlyingError: Error = (error?.takeRetainedValue() as Error?) ?? NSError(domain: "SecureEnclaveError", code: -50)
            
            // Check for specific error codes
            if let nsError = underlyingError as NSError? {
                if nsError.code == -34018 { // errSecMissingEntitlement
                    throw NailedCoreError.missingEntitlement
                }
            }
            
            throw NSError(domain: "SecureEnclaveError",
                         code: -50,
                         userInfo: [
                            NSLocalizedDescriptionKey: "failed to generate key",
                            NSUnderlyingErrorKey: underlyingError
                         ])
        }

        return key
    }
    
    /// Get the private key from the Secure Enclave
    private func getPrivateKey() throws -> SecKey? {
        guard let tagData = tag.data(using: .utf8) else {
            throw NSError(domain: "SecureEnclaveError",
                          code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to encode tag data"])
        }

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
            throw NSError(domain: NSOSStatusErrorDomain,
                          code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Failed to retrieve private key, status: \(status)"])
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
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            // kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecValueRef as String: certificate
        ]

        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
    
    /// Sign data using the private key
    private func sign(digest: Data, privateKey: SecKey) throws -> Data {
        precondition(digest.count == 32, "OpenVPN always supplies a 32-byte digest")
        
        let alg = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, alg) else {
            throw NSError(domain: NSOSStatusErrorDomain,
                          code: Int(errSecUnimplemented),
                          userInfo: [NSLocalizedDescriptionKey:
                                     "Key does not support ECDSA-SHA256 digest signing"])
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, alg, digest as CFData, &error) as Data? else {
            if let err = error?.takeRetainedValue() {
                throw err as Error
            }
            throw NSError(domain: "SecKeyError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create signature"])
        }

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
        guard let tagData = tag.data(using: .utf8) else {
            throw NSError(domain: "SecureEnclaveError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode tag data"])
        }

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
    }
    
    // MARK: - Public Interface
    
    /// Check if an identity exists in the Secure Enclave
    public func hasIdentity() throws -> Bool {
        return try getPrivateKey() != nil
    }
    
    /// Generate the single identity with a secure enclave key pair
    public func generateIdentity() throws {
        // Delete any existing identity first
        try? deleteIdentity()
        
        do {
            _ = try generateKey()
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "generate key",
                underlyingError: error
            )
        }
    }
    
    /// Import a certificate for the identity
    public func importCertificate(certificateData: Data) throws {
        guard try hasIdentity() else {
            throw NailedCoreError.identityNotFound
        }
        
        // Convert certificate data to SecCertificate
        guard let secCertificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw NailedCoreError.invalidCertificateData(
                reason: "Unable to create SecCertificate from provided data"
            )
        }
        
        // Import certificate
        do {
            try importCertificate(secCertificate)
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "import certificate",
                underlyingError: error
            )
        }
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
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        // Generate CSR
        let csr: CertificateSigningRequest
        do {
            csr = try generateCSR(privateKey: privateKey, commonName: commonName)
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "generate CSR with CN=\(commonName)",
                underlyingError: error
            )
        }
        
        // Serialize to DER format
        do {
            var serializer = DER.Serializer()
            try csr.serialize(into: &serializer)
            return Data(serializer.serializedBytes)
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "serialize CSR",
                underlyingError: error
            )
        }
    }
    
    /// Sign data using the identity's private key
    public func sign(data: Data) throws -> Data {
        guard let privateKey = try getPrivateKey() else {
            throw NailedCoreError.privateKeyNotFound
        }
        
        // Sign the data
        do {
            return try sign(digest: data, privateKey: privateKey)
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "sign data",
                underlyingError: error
            )
        }
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
        
        do {
            return try exportPublicKey(privateKey: privateKey)
        } catch {
            throw NailedCoreError.enclaveOperationFailed(
                operation: "export public key",
                underlyingError: error
            )
        }
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
