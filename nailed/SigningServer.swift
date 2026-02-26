// SPDX-License-Identifier: Apache-2.0

import Foundation
import Network

class UnixSigningServer: ObservableObject {
    @Published var isRunning = false
    @Published var socketPath: String = "/tmp/nailed_signing.sock"
    @Published var statusMessage = "Server stopped"
    @Published var errorMessage = ""
    
    private var listener: NWListener?
    private var handler: ManagementCommandHandler?
    private var activeConnections: [NWConnection] = []
    private let log = NailedLogger.shared
    
    init(core: (any NailedCoreProtocol)?) {
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
        guard !isRunning else { return }
        
        // Clean up any existing socket file
        try? FileManager.default.removeItem(atPath: socketPath)
        
        // Create parameters for Unix domain socket using the correct approach
        let params = NWParameters(tls: nil, tcp: .init())
        
        // Force the bind point to a Unix-domain path
        params.requiredLocalEndpoint = .unix(path: socketPath)
        
        // Reuse the same path on restart, and let anyone connect
        params.allowLocalEndpointReuse = true
        
        do {
            // Create the listener; no endpoint argument needed
            listener = try NWListener(using: params)
        } catch {
            errorMessage = "Failed to create listener: \(error.localizedDescription)"
            return
        }
        
        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }
        
        listener?.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    self?.isRunning = true
                    self?.statusMessage = "Management server running on \(self?.socketPath ?? "")"
                    self?.errorMessage = ""
                case .failed(let error):
                    self?.isRunning = false
                    self?.statusMessage = "Management server failed"
                    self?.errorMessage = "Server failed: \(error.localizedDescription)"
                case .cancelled:
                    self?.isRunning = false
                    self?.statusMessage = "Management server stopped"
                    self?.errorMessage = ""
                    // Clean up socket file when server stops
                    if let path = self?.socketPath {
                        try? FileManager.default.removeItem(atPath: path)
                    }
                default:
                    break
                }
            }
        }
        
        listener?.start(queue: .main)
    }
    
    func stopServer() {
        // Close all active connections
        for connection in activeConnections {
            connection.cancel()
        }
        activeConnections.removeAll()
        
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
            self.statusMessage = "Management server stopped"
            self.errorMessage = ""
            // Clean up socket file
            try? FileManager.default.removeItem(atPath: self.socketPath)
        }
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