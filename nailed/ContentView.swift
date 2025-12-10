// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers
import AppKit

struct ContentView: View {
    // Single instance of the library
    @State private var core: NailedCore?
    
    // Unix Socket Server
    @StateObject private var unixServer = UnixSigningServer(core: nil)
    
    // UI-state for single identity
    @State private var hasIdentity: Bool = false
    @State private var hasCertificate: Bool = false
    @State private var certificateInfo: CertificateInfo?
    @State private var errorMessage: String = ""

    // CSR generation state
    // @State private var commonName: String = ""
    @State private var generatedCSR: String = ""
    @State private var showingCSRGenerator: Bool = false
    @State private var showingCSRExporter: Bool = false
    
    // Certificate import state
    @State private var showingCertImporter: Bool = false
    @State private var showingDeleteConfirmation: Bool = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                errorSection
                serverSection
                identitySection
                
                actionButtonsSection
            }
            .padding()
        }
        .task {
            initializeCore()
        }
        .sheet(isPresented: $showingCSRGenerator, content: {
            CSRGeneratorView(
                core: core,
                onGenerate: { commonName in
                    generateCSR(commonName: commonName)
                }
            )
        })
        .fileExporter(
            isPresented: $showingCSRExporter,
            document: CSRDocument(content: generatedCSR),
            contentType: .data,
            defaultFilename: "certificate_request",
            onCompletion: { result in
            switch result {
            case .success:
                break
            case .failure(let error):
                errorMessage = "Failed to save CSR: \(error.localizedDescription)"
            }
        })
        .fileImporter(
            isPresented: $showingCertImporter,
            allowedContentTypes: [.x509Certificate, .data, .plainText],
            allowsMultipleSelection: false,
            onCompletion: { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    importCertificateFromFile(url: url)
                }
            case .failure(let error):
                errorMessage = "Failed to import certificate: \(error.localizedDescription)"
            }
        })
        .alert("Delete Identity", isPresented: $showingDeleteConfirmation, actions: {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                deleteIdentity()
            }
        }, message: {
            Text("Are you sure you want to delete the identity? This action cannot be undone.")
        })
    }
    
    // MARK: - View Components
    
    @ViewBuilder
    private var errorSection: some View {
        if !errorMessage.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.red)
                    Text("Error Details:")
                        .font(.headline)
                        .foregroundColor(.red)
                    Spacer()
                    Button(action: { errorMessage = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                    Text("Click to copy")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Button(action: {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(errorMessage, forType: .string)
                }) {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .font(.footnote)
                        .multilineTextAlignment(.leading)
                        .textSelection(.enabled)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.red.opacity(0.3), lineWidth: 1)
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
        }
    }
    
    @ViewBuilder
    private var serverSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Signing Server")
                .font(.headline)
            
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Image(systemName: unixServer.isRunning ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(unixServer.isRunning ? .green : .red)
                    Text(unixServer.statusMessage)
                        .font(.body)
                }
                
                if !unixServer.errorMessage.isEmpty {
                    Text(unixServer.errorMessage)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
            // Statistics
            if unixServer.isRunning || unixServer.totalConnections > 0 {
                Divider()
                
                HStack(spacing: 16) {
                    StatBadge(
                        icon: "cable.connector",
                        label: "Connections",
                        value: unixServer.totalConnections,
                        color: .blue
                    )
                    
                    StatBadge(
                        icon: "signature",
                        label: "Signatures",
                        value: unixServer.signCommands,
                        color: .purple
                    )
                    
                    StatBadge(
                        icon: "doc.badge.plus",
                        label: "Certificates",
                        value: unixServer.certificateCommands,
                        color: .orange
                    )
                    
                    if unixServer.errorCount > 0 {
                        StatBadge(
                            icon: "exclamationmark.triangle",
                            label: "Errors",
                            value: unixServer.errorCount,
                            color: .red
                        )
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(
            unixServer.isRunning ?
            Color.green.opacity(0.15) :
            Color.gray.opacity(0.1)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(
                    unixServer.isRunning ?
                    Color.green.opacity(0.3) :
                    Color.clear,
                    lineWidth: 2
                )
        )
        .cornerRadius(8)
    }
    
    @ViewBuilder
    private var identitySection: some View {
        if hasIdentity {
            VStack(alignment: .leading, spacing: 12) {
                Text("Identity Status:")
                    .font(.headline)
                
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Image(systemName: "key.fill")
                            .foregroundColor(.green)
                        Text("Private key: Available")
                            .font(.body)
                    }
                    
                    HStack {
                        Image(systemName: hasCertificate ? "checkmark.seal.fill" : "xmark.seal.fill")
                            .foregroundColor(hasCertificate ? .green : .red)
                        Text("Certificate: \(hasCertificate ? "Available" : "Not available")")
                            .font(.body)
                            .fontWeight(hasCertificate ? .semibold : .regular)
                    }
                    
                    if let certInfo = certificateInfo {
                        VStack(alignment: .leading, spacing: 2) {
                            if let commonName = certInfo.commonName {
                                Text("CN: \(commonName)")
                                    .font(.caption)
                                    .foregroundColor(.primary)
                            }
                            
                            if let issuer = certInfo.issuerCommonName {
                                Text("Issuer: \(issuer)")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            
                            Text("Valid: \(formattedDateRange(from: certInfo.notValidBefore, to: certInfo.notValidAfter))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.leading, 20)
                    }
                }
                // Action buttons
                HStack(spacing: 12) {
                    Button(action: {
                        showingCSRGenerator = true
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "doc.text")
                            Text("Generate CSR")
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    
                    Button(action: {
                        showingCertImporter = true
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "square.and.arrow.down")
                            Text("Import Certificate")
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    
                    Button(action: {
                        showingDeleteConfirmation = true
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "trash")
                            Text("Delete Identity")
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .foregroundColor(.red)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
            .background(
                hasCertificate ?
                Color.green.opacity(0.15) :
                Color.gray.opacity(0.1)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(
                        hasCertificate ?
                        Color.green.opacity(0.3) :
                        Color.clear,
                        lineWidth: 2
                    )
            )
            .cornerRadius(8)
        }
    }
    
    private func formattedDateRange(from start: Date, to end: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .none
        
        return "\(formatter.string(from: start)) - \(formatter.string(from: end))"
    }
    
    @ViewBuilder
    private var actionButtonsSection: some View {
        if !hasIdentity {
            Button(action: {
                generateIdentity()
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "key.fill")
                    Text("Generate Identity")
                }
            }
            .disabled(core == nil)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }
    
    // MARK: - Actions
    
    private func initializeCore() {
        do {
            core = try NailedCore()
            updateServerCore()
            unixServer.startServer()
            updateIdentityState()
        } catch {
            errorMessage = "Failed to initialize core: \(error.localizedDescription)"
        }
    }
    
    private func updateServerCore() {
        unixServer.updateCore(core)
    }
    
    private func generateIdentity() {
        guard let core = core else { return }
        
        do {
            try core.generateIdentity()
            updateIdentityState()
        } catch {
            errorMessage = "Failed to generate identity: \(error.localizedDescription)"
        }
    }
    
    private func updateIdentityState() {
        guard let core = core else { return }
        
        do {
            hasIdentity = try core.hasIdentity()
            
            if hasIdentity {
                hasCertificate = try core.hasCertificate()
                certificateInfo = try core.getCertificateInfo()
            } else {
                hasCertificate = false
                certificateInfo = nil
            }
        } catch {
            errorMessage = "Failed to check identity status: \(error.localizedDescription)"
        }
    }
    
    private func deleteIdentity() {
        guard let core = core else { return }
        
        do {
            try core.deleteIdentity()
            hasIdentity = false
            hasCertificate = false
            certificateInfo = nil
        } catch {
            errorMessage = "Failed to delete identity: \(error.localizedDescription)"
        }
    }
    
    private func generateCSR(commonName: String) {
        guard let core = core else { return }
        
        do {
            let csrData = try core.generateCSR(commonName: commonName)
            let base64CSR = csrData.base64EncodedString()
            generatedCSR = [
                "-----BEGIN CERTIFICATE REQUEST-----",
                base64CSR,
                "-----END CERTIFICATE REQUEST-----"
            ].joined(separator: "\n")
            showingCSRExporter = true
        } catch {
            errorMessage = "Failed to generate CSR: \(error.localizedDescription)"
        }
    }
    
    private func importCertificateFromFile(url: URL) {
        guard let core = core else { return }
        guard url.startAccessingSecurityScopedResource() else {
            errorMessage = "Failed to access selected file"
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let fileData = try Data(contentsOf: url)
            let certificateData = try parseCertificateData(from: fileData)
            try core.importCertificate(certificateData: certificateData)
            updateIdentityState() // Refresh to show the new certificate
        } catch {
            // Debug print
            print("[Import Certificate Error]", error)
            // Handle NailedCoreError.enclaveOperationFailed
            if let nailedError = error as? NailedCoreError {
                switch nailedError {
                case .enclaveOperationFailed(_, let underlyingError):
                    if let nsError = underlyingError as NSError?, nsError.domain == "OSStatus" {
                        switch nsError.code {
                        case -25299:
                            errorMessage = "Certificate already exists: This certificate is already imported in the keychain."
                        case -25300:
                            errorMessage = "Certificate not found: No matching private key found for this certificate."
                        default:
                            errorMessage = "OSStatus error (code: \(nsError.code)): \(nsError.localizedDescription)"
                        }
                        return
                    }
                default: break
                }
            }
            // Fallback: check for direct NSError
            if let nsError = error as NSError?, nsError.domain == "OSStatus" {
                switch nsError.code {
                case -25299:
                    errorMessage = "Certificate already exists: This certificate is already imported in the keychain."
                case -25300:
                    errorMessage = "Certificate not found: No matching private key found for this certificate."
                default:
                    errorMessage = "OSStatus error (code: \(nsError.code)): \(nsError.localizedDescription)"
                }
            } else {
                let nsError = error as NSError
                errorMessage = "Failed to import certificate: \(nsError.localizedDescription)\nDomain: \(nsError.domain)\nCode: \(nsError.code)"
            }
        }
    }
    
    private func parseCertificateData(from fileData: Data) throws -> Data {
        // First, try to parse as string (PEM format)
        if let pemString = String(data: fileData, encoding: .utf8) {
            // Trim whitespace from beginning and end
            let trimmedPemString = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
            
            // Remove PEM headers and decode base64
            let cleanPemString = trimmedPemString
                .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
                .replacingOccurrences(of: " ", with: "")
            
            if let base64Data = Data(base64Encoded: cleanPemString) {
                return base64Data
            }
        }
        
        // If PEM parsing failed, assume it's already in DER format
        return fileData
    }
}

// MARK: - CSR Generator View
struct CSRGeneratorView: View {
    let core: NailedCore?
    let onGenerate: (String) -> Void
    
    @State private var commonName: String = ""
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        VStack(spacing: 24) {
            commonNameInputSection
            buttonSection
            Button("Cancel") {
                dismiss()
            }
            .buttonStyle(.bordered)
        }
        .padding(32)
        .frame(minWidth: 340)
    }
    
    private var commonNameInputSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Common Name (CN):")
                .font(.headline)
            TextField("e.g., John Doe", text: $commonName)
                .textFieldStyle(.roundedBorder)
        }
    }
    
    private var buttonSection: some View {
        Button(action: {
            onGenerate(commonName)
            dismiss()
        }) {
            HStack(spacing: 8) {
                Image(systemName: "doc.text")
                Text("Generate CSR")
            }
            .frame(maxWidth: .infinity)
        }
        .disabled(commonName.isEmpty || core == nil)
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
    }
}

// MARK: - Stat Badge Component
struct StatBadge: View {
    let icon: String
    let label: String
    let value: Int
    let color: Color
    
    var body: some View {
        VStack(spacing: 2) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.caption)
                Text("\(value)")
                    .font(.system(.body, design: .monospaced))
                    .fontWeight(.semibold)
            }
            .foregroundColor(color)
            
            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .frame(minWidth: 70)
    }
}

// MARK: - CSR Document for File Export
struct CSRDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    
    var content: String
    
    init(content: String) {
        self.content = content
    }
    
    init(configuration: ReadConfiguration) throws {
        content = ""
    }
    
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let data = content.data(using: .utf8) ?? Data()
        return FileWrapper(regularFileWithContents: data)
    }
}

#Preview {
    ContentView()
}
