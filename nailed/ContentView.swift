// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers
import AppKit

struct ContentView: View {
    @EnvironmentObject private var appService: AppService

    // UI-only presentation state
    @State private var csrCommonName: String = ""
    @State private var generatedCSR: String = ""
    @State private var showingCSRGenerator: Bool = false
    @State private var showingCSRExporter: Bool = false
    @State private var showingCertImporter: Bool = false
    @State private var showingDeleteConfirmation: Bool = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                errorSection
                serverSection
                identitySection
                
                actionButtonsSection
                
                HStack {
                    Text("nailed \(AppVersion.version)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    
                    Spacer()
                    
                    Button(action: { shareLogFile() }) {
                        HStack(spacing: 4) {
                            Image(systemName: "doc.text")
                            Text("Export Log")
                        }
                        .font(.caption2)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(!FileManager.default.fileExists(atPath: NailedLogger.shared.logFileURL.path))
                }
            }
            .padding()
        }
        .sheet(isPresented: $showingCSRGenerator, content: {
            CSRGeneratorView(
                isReady: appService.isReady,
                onGenerate: { commonName in
                    generateCSR(commonName: commonName)
                }
            )
        })
        .fileExporter(
            isPresented: $showingCSRExporter,
            document: CSRDocument(content: generatedCSR),
            contentType: .certificateSigningRequest,
            defaultFilename: csrCommonName,
            onCompletion: { result in
            switch result {
            case .success:
                break
            case .failure(let error):
                appService.errorMessage = "Failed to save CSR: \(error.localizedDescription)"
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
                    appService.importCertificate(from: url)
                }
            case .failure(let error):
                appService.errorMessage = "Failed to import certificate: \(error.localizedDescription)"
            }
        })
        .alert("Delete Identity", isPresented: $showingDeleteConfirmation, actions: {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                appService.deleteIdentity()
            }
        }, message: {
            Text("Are you sure you want to delete the identity? This action cannot be undone.")
        })
    }
    
    // MARK: - View Components
    
    @ViewBuilder
    private var errorSection: some View {
        if !appService.errorMessage.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.red)
                    Text("Error Details:")
                        .font(.headline)
                        .foregroundColor(.red)
                    Spacer()
                    Button(action: { appService.errorMessage = "" }) {
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
                    pasteboard.setString(appService.errorMessage, forType: .string)
                }) {
                    Text(appService.errorMessage)
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
                    Image(systemName: appService.serverStatus.isRunning ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(appService.serverStatus.isRunning ? .green : .red)
                    Text(appService.serverStatus.statusMessage)
                        .font(.body)
                }
                
                if !appService.serverStatus.errorMessage.isEmpty {
                    Text(appService.serverStatus.errorMessage)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(
            appService.serverStatus.isRunning ?
            Color.green.opacity(0.15) :
            Color.gray.opacity(0.1)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(
                    appService.serverStatus.isRunning ?
                    Color.green.opacity(0.3) :
                    Color.clear,
                    lineWidth: 2
                )
        )
        .cornerRadius(8)
    }
    
    @ViewBuilder
    private var identitySection: some View {
        if appService.hasIdentity {
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
                        Image(systemName: appService.hasCertificate ? "checkmark.seal.fill" : "xmark.seal.fill")
                            .foregroundColor(appService.hasCertificate ? .green : .red)
                        Text("Certificate: \(appService.hasCertificate ? "Available" : "Not available")")
                            .font(.body)
                            .fontWeight(appService.hasCertificate ? .semibold : .regular)
                    }
                    
                    if let certInfo = appService.certificateInfo {
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
                appService.hasCertificate ?
                Color.green.opacity(0.15) :
                Color.gray.opacity(0.1)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(
                        appService.hasCertificate ?
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
        if !appService.hasIdentity {
            Button(action: {
                appService.generateIdentity()
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "key.fill")
                    Text("Generate Identity")
                }
            }
            .disabled(!appService.isReady)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }
    
    // MARK: - Local UI actions

    private func generateCSR(commonName: String) {
        csrCommonName = commonName
        if let pem = appService.generateCSR(commonName: commonName) {
            generatedCSR = pem
            showingCSRExporter = true
        }
    }

    private func shareLogFile() {
        let logURL = NailedLogger.shared.logFileURL
        guard FileManager.default.fileExists(atPath: logURL.path) else { return }
        
        let panel = NSSavePanel()
        panel.nameFieldStringValue = logURL.lastPathComponent
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        
        panel.begin { response in
            guard response == .OK, let destURL = panel.url else { return }
            do {
                if FileManager.default.fileExists(atPath: destURL.path) {
                    try FileManager.default.removeItem(at: destURL)
                }
                try FileManager.default.copyItem(at: logURL, to: destURL)
            } catch {
                NailedLogger.shared.error("Failed to save log file: \(error.localizedDescription)", category: "ui")
            }
        }
    }
}

// MARK: - CSR Generator View
struct CSRGeneratorView: View {
    let isReady: Bool
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
        .disabled(commonName.isEmpty || !isReady)
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
    }
}

// MARK: - UTType for CSR files
extension UTType {
    static var certificateSigningRequest: UTType {
        UTType(filenameExtension: "csr") ?? .data
    }
}

// MARK: - CSR Document for File Export
struct CSRDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.certificateSigningRequest] }
    
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
        .environmentObject(AppService())
}
