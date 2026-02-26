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
    private var handler: ManagementCommandHandler?
    private var activeConnections: [NWConnection] = []
    private let log = NailedLogger.shared
    
    init(core: (any NailedCoreProtocol)?, socketPath: String = "/tmp/nailed_signing.sock") {
        self.socketPath = socketPath
        if let core { self.handler = ManagementCommandHandler(core: core) }
    }
    
    func updateCore(_ core: (any NailedCoreProtocol)?) {
        if let core {
            self.handler = ManagementCommandHandler(core: core)
        } else {
            self.handler = nil
        }
    }
    
    func startServer() {
        guard !status.isRunning else { return }
        
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
            case .ready:
                self.status.isRunning = true
                self.status.statusMessage = "Management server running on \(self.socketPath)"
                self.status.errorMessage = ""
            case .failed(let error):
                self.status.isRunning = false
                self.status.statusMessage = "Management server failed"
                self.status.errorMessage = "Server failed: \(error.localizedDescription)"
            case .cancelled:
                self.status.isRunning = false
                self.status.statusMessage = "Management server stopped"
                self.status.errorMessage = ""
                try? FileManager.default.removeItem(atPath: self.socketPath)
            default:
                return
            }
            self.onStatusChange?(self.status)
        }
        
        listener?.start(queue: .main)
    }
    
    func stopServer() {
        for connection in activeConnections {
            connection.cancel()
        }
        activeConnections.removeAll()
        
        listener?.cancel()
        listener = nil
        status.isRunning = false
        status.statusMessage = "Management server stopped"
        status.errorMessage = ""
        try? FileManager.default.removeItem(atPath: socketPath)
        onStatusChange?(status)
    }
    
    private func handleNewConnection(_ connection: NWConnection) {
        log.info("New management connection received", category: "server")
        activeConnections.append(connection)
        
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.log.info("Management connection ready", category: "server")
                self?.receiveMessage(from: connection)
            case .failed(let error):
                self?.log.error("Management connection failed: \(error)", category: "server")
                self?.removeConnection(connection)
            case .cancelled:
                self?.log.debug("Management connection cancelled", category: "server")
                self?.removeConnection(connection)
            default:
                break
            }
        }
        
        connection.start(queue: .global(qos: .background))
    }
    
    private func removeConnection(_ connection: NWConnection) {
        if let index = activeConnections.firstIndex(where: { $0 === connection }) {
            activeConnections.remove(at: index)
        }
    }
    
    private func receiveMessage(from connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, isComplete, error in
            if let error = error {
                self?.log.error("Receive error: \(error)", category: "server")
                self?.removeConnection(connection)
                return
            }
            
            if let data = data, !data.isEmpty {
                if let message = String(data: data, encoding: .utf8) {
                    self?.log.debug("Received management message: '\(message)'", category: "server")
                    self?.processMessage(message.trimmingCharacters(in: .whitespacesAndNewlines), connection: connection)
                } else {
                    self?.log.warning("Failed to decode message as UTF-8", category: "server")
                    self?.sendResponse("ERROR: Invalid UTF-8 encoding\r\n", to: connection)
                }
            }
            
            if isComplete {
                self?.log.info("Management connection closed by client", category: "server")
                self?.removeConnection(connection)
            } else {
                // Continue listening for more messages
                self?.receiveMessage(from: connection)
            }
        }
    }
    
    private func processMessage(_ message: String, connection: NWConnection) {
        guard let handler = handler else {
            let error = "ERROR: No core available\r\n"
            sendResponse(error, to: connection)
            return
        }
        for response in handler.handleMessage(message) {
            sendResponse(response, to: connection)
        }
    }
    
    private func sendResponse(_ response: String, to connection: NWConnection) {
        guard let data = response.data(using: .utf8) else {
            log.error("Failed to encode response as UTF-8", category: "server")
            return
        }
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.log.error("Send error: \(error)", category: "server")
            } else {
                self?.log.debug("Response sent successfully, waiting for more requests", category: "server")
            }
            // Keep connection alive for more requests
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