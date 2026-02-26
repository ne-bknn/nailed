// SPDX-License-Identifier: Apache-2.0

import Foundation
import Combine
import AppKit

final class AppService: ObservableObject {

    // MARK: - Published state

    @Published private(set) var hasIdentity: Bool = false
    @Published private(set) var hasCertificate: Bool = false
    @Published private(set) var certificateInfo: CertificateInfo?
    @Published var errorMessage: String = ""

    // MARK: - Owned objects

    private(set) var core: NailedCore?
    let server: UnixSigningServer

    var isReady: Bool { core != nil }

    // MARK: - Private

    private let log = NailedLogger.shared
    private var serverCancellable: AnyCancellable?

    // MARK: - Init

    init() {
        self.server = UnixSigningServer(core: nil)
        serverCancellable = server.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
    }

    // MARK: - Lifecycle

    func start() {
        do {
            let core = try NailedCore()
            self.core = core
            server.updateCore(core)
            server.startServer()
            refreshState()
            log.info("Core initialized successfully", category: "app")
        } catch {
            log.error("Failed to initialize core: \(error.localizedDescription)", category: "app")
            errorMessage = "Failed to initialize core: \(error.localizedDescription)"
        }
    }

    // MARK: - Actions

    func generateIdentity() {
        guard let core = core else { return }

        do {
            log.info("User requested identity generation", category: "app")
            try core.generateIdentity()
            refreshState()
        } catch {
            log.error("Failed to generate identity: \(error.localizedDescription)", category: "app")
            errorMessage = "Failed to generate identity: \(error.localizedDescription)"
        }
    }

    func deleteIdentity() {
        guard let core = core else { return }

        do {
            log.info("User requested identity deletion", category: "app")
            try core.deleteIdentity()
            hasIdentity = false
            hasCertificate = false
            certificateInfo = nil
        } catch {
            log.error("Failed to delete identity: \(error.localizedDescription)", category: "app")
            errorMessage = "Failed to delete identity: \(error.localizedDescription)"
        }
    }

    /// Generate a CSR and return the PEM string, or nil on failure.
    func generateCSR(commonName: String) -> String? {
        guard let core = core else { return nil }

        do {
            log.info("User requested CSR generation for CN=\(commonName)", category: "app")
            let csrData = try core.generateCSR(commonName: commonName)
            let base64CSR = csrData.base64EncodedString()
            return [
                "-----BEGIN CERTIFICATE REQUEST-----",
                base64CSR,
                "-----END CERTIFICATE REQUEST-----"
            ].joined(separator: "\n")
        } catch {
            log.error("Failed to generate CSR: \(error.localizedDescription)", category: "app")
            errorMessage = "Failed to generate CSR: \(error.localizedDescription)"
            return nil
        }
    }

    func importCertificate(from url: URL) {
        guard let core = core else { return }
        log.info("User importing certificate from \(url.lastPathComponent)", category: "app")

        guard url.startAccessingSecurityScopedResource() else {
            log.error("Failed to access security-scoped resource: \(url.path)", category: "app")
            errorMessage = "Failed to access selected file"
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }

        do {
            let fileData = try Data(contentsOf: url)
            let certificateData = NailedCore.parseCertificateData(from: fileData)
            try core.importCertificate(certificateData: certificateData)
            refreshState()
        } catch let error as NailedCoreError {
            log.error("Certificate import error: \(error.localizedDescription)", category: "app")
            switch error {
            case .certificateAlreadyExists:
                errorMessage = "Certificate already exists in the keychain."
            case .invalidCertificateData(let reason):
                errorMessage = "Invalid certificate: \(reason)"
            default:
                errorMessage = "Failed to import certificate: \(error.localizedDescription)"
            }
        } catch {
            log.error("Certificate import error: \(error.localizedDescription)", category: "app")
            errorMessage = "Failed to import certificate: \(error.localizedDescription)"
        }
    }

    // MARK: - State refresh

    func refreshState() {
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
}
