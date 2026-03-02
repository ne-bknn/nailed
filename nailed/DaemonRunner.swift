// SPDX-License-Identifier: Apache-2.0

import Foundation

enum DaemonRunner {
    static func run() -> Never {
        let log = NailedLogger.shared
        log.info("Starting daemon mode", category: "daemon")

        let core: NailedCore
        do {
            core = try NailedCore()
        } catch {
            log.error("Failed to init core: \(error.localizedDescription)", category: "daemon")
            exit(1)
        }

        let server = UnixSigningServer(core: core)
        server.startServer()

        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signal(SIGTERM, SIG_IGN)
        sigterm.setEventHandler {
            log.info("SIGTERM received, shutting down", category: "daemon")
            server.stopServer()
            exit(0)
        }
        sigterm.resume()

        log.info("Daemon running, PID \(ProcessInfo.processInfo.processIdentifier)", category: "daemon")
        RunLoop.main.run()
        exit(0)
    }
}
