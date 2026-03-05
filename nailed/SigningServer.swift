// SPDX-License-Identifier: Apache-2.0

import Foundation
import Network

struct ServerStatus {
    var isRunning: Bool = false
    var statusMessage: String = "Server stopped"
    var errorMessage: String = ""
}

class UnixSigningServer {
    private(set) var status = ServerStatus()
    let socketPath: String
    var onStatusChange: ((ServerStatus) -> Void)?

    private var listener: NWListener?
    private var core: (any NailedCoreProtocol)?
    private var activeConnections: [NWConnection] = []
    private var sessions: [ObjectIdentifier: Session] = [:]
    private let log: any LoggerProtocol

    init(core: (any NailedCoreProtocol)?, socketPath: String = "/tmp/nailed_signing.sock", logger: any LoggerProtocol = NailedLogger.shared) {
        self.socketPath = socketPath
        self.log = logger
        self.core = core
    }

    func updateCore(_ core: (any NailedCoreProtocol)?) {
        self.core = core
    }
    
    func startServer() {
        log.info("startServer() called, isRunning=\(status.isRunning)", category: "server")
        guard !status.isRunning else {
            log.info("startServer() skipped: already running", category: "server")
            return
        }
        
        try? FileManager.default.removeItem(atPath: socketPath)
        
        let params = NWParameters(tls: nil, tcp: .init())
        params.requiredLocalEndpoint = .unix(path: socketPath)
        params.allowLocalEndpointReuse = true
        
        do {
            listener = try NWListener(using: params)
        } catch {
            status.errorMessage = "Failed to create listener: \(error.localizedDescription)"
            onStatusChange?(status)
            return
        }
        
        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }
        
        listener?.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .setup:
                self.log.debug("Listener state: setup", category: "server")
                return
            case .waiting(let error):
                self.log.warning("Listener state: waiting (\(error.localizedDescription))", category: "server")
                return
            case .ready:
                self.log.info("Listener state: ready on \(self.socketPath)", category: "server")
                self.status.isRunning = true
                self.status.statusMessage = "Management server running on \(self.socketPath)"
                self.status.errorMessage = ""
            case .failed(let error):
                self.log.error("Listener state: failed (\(error.localizedDescription))", category: "server")
                self.status.isRunning = false
                self.status.statusMessage = "Management server failed"
                self.status.errorMessage = "Server failed: \(error.localizedDescription)"
            case .cancelled:
                self.log.info("Listener state: cancelled", category: "server")
                self.status.isRunning = false
                self.status.statusMessage = "Management server stopped"
                self.status.errorMessage = ""
                try? FileManager.default.removeItem(atPath: self.socketPath)
            @unknown default:
                self.log.warning("Listener state: unknown (\(state))", category: "server")
                return
            }
            self.onStatusChange?(self.status)
        }
        
        listener?.start(queue: .main)
    }
    
    func stopServer() {
        log.info("stopServer() called, \(activeConnections.count) active connections", category: "server")
        for connection in activeConnections {
            connection.cancel()
        }
        activeConnections.removeAll()
        sessions.removeAll()

        listener?.cancel()
        listener = nil
        status.isRunning = false
        status.statusMessage = "Management server stopped"
        status.errorMessage = ""
        try? FileManager.default.removeItem(atPath: socketPath)
        onStatusChange?(status)
    }
    
    private func handleNewConnection(_ connection: NWConnection) {
        log.info("New connection received", category: "server")
        activeConnections.append(connection)

        if let core {
            let session = Session(core: core, logger: log)
            sessions[ObjectIdentifier(connection)] = session
        }

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.log.info("Connection ready", category: "server")
                self?.receiveMessage(from: connection)
            case .failed(let error):
                self?.log.error("Connection failed: \(error)", category: "server")
                self?.removeConnection(connection)
            case .cancelled:
                self?.log.debug("Connection cancelled", category: "server")
                self?.removeConnection(connection)
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .background))
    }

    private func removeConnection(_ connection: NWConnection) {
        sessions.removeValue(forKey: ObjectIdentifier(connection))
        if let index = activeConnections.firstIndex(where: { $0 === connection }) {
            activeConnections.remove(at: index)
        }
    }
    
    private func receiveMessage(from connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, error in
            if let error = error {
                self?.log.error("Receive error: \(error)", category: "server")
                self?.removeConnection(connection)
                return
            }

            if let data = data, !data.isEmpty {
                guard let message = String(data: data, encoding: .utf8) else {
                    self?.log.warning("Failed to decode message as UTF-8", category: "server")
                    self?.sendResponse(Data(#"{"ok":false,"error":"invalid UTF-8"}"#.utf8), to: connection)
                    return
                }

                for line in message.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty else { continue }
                    self?.processMessage(Data(trimmed.utf8), connection: connection)
                }
            }

            if isComplete {
                self?.log.info("Connection closed by client", category: "server")
                self?.removeConnection(connection)
            } else {
                self?.receiveMessage(from: connection)
            }
        }
    }

    private func processMessage(_ data: Data, connection: NWConnection) {
        guard let session = sessions[ObjectIdentifier(connection)] else {
            let error = Data(#"{"ok":false,"error":"no core available"}"#.utf8)
            sendResponse(error, to: connection)
            return
        }
        let response = session.handleRequest(data)
        sendResponse(response, to: connection)
    }

    private func sendResponse(_ data: Data, to connection: NWConnection) {
        var payload = data
        payload.append(contentsOf: [0x0A]) // newline delimiter
        connection.send(content: payload, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.log.error("Send error: \(error)", category: "server")
            }
        })
    }
    
}

// MARK: - String Extension for PEM formatting

extension String {
    /// Splits the string into chunks of specified size
    func chunked(into size: Int) -> [String] {
        var chunks: [String] = []
        var startIndex = self.startIndex
        
        while startIndex < self.endIndex {
            let endIndex = self.index(startIndex, offsetBy: size, limitedBy: self.endIndex) ?? self.endIndex
            chunks.append(String(self[startIndex..<endIndex]))
            startIndex = endIndex
        }
        
        return chunks
    }
}