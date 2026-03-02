// SPDX-License-Identifier: Apache-2.0

import Foundation
import AppKit

final class AppService: ObservableObject {

    // MARK: - Published state

    @Published private(set) var hasIdentity: Bool = false
    @Published private(set) var hasCertificate: Bool = false
    @Published private(set) var certificateInfo: CertificateInfo?
    @Published private(set) var serverStatus = ServerStatus()

    // MARK: - Owned objects

    private(set) var core: (any NailedCoreProtocol)?
    private let server: UnixSigningServer

    var isReady: Bool { core != nil }

    // MARK: - Private

    private let log = NailedLogger.shared

    // MARK: - Init

    init() {
        self.server = UnixSigningServer(core: nil)
        server.onStatusChange = { [weak self] status in
            DispatchQueue.main.async {
                self?.serverStatus = status
            }
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
        }
    }

    func stopServer() {
        server.stopServer()
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
            log.error("Failed to check identity status: \(error.localizedDescription)", category: "app")
        }
    }
}
