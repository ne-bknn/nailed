// SPDX-License-Identifier: Apache-2.0

import Foundation
import Network

class UnixSigningServer: ObservableObject {
    @Published var isRunning = false
    @Published var socketPath: String = "/tmp/nailed_signing.sock"
    @Published var statusMessage = "Server stopped"
    @Published var errorMessage = ""
    
    // Statistics
    @Published var totalConnections: Int = 0
    @Published var signCommands: Int = 0
    @Published var certificateCommands: Int = 0
    @Published var errorCount: Int = 0
    
    private var listener: NWListener?
    private var core: NailedCore?
    private var activeConnections: [NWConnection] = []
    private let log = NailedLogger.shared
    
    init(core: NailedCore?) {
        self.core = core
    }
    
    func updateCore(_ core: NailedCore?) {
        self.core = core
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
        DispatchQueue.main.async {
            self.totalConnections += 1
        }
        
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
                    self?.sendError("Invalid UTF-8 encoding", to: connection)
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
        log.debug("Processing management message: '\(message)'", category: "server")
        
        // Split message by lines and process each command that starts with '>'
        let lines = message.components(separatedBy: .newlines)
        
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            
            // Skip empty lines
            guard !trimmedLine.isEmpty else { continue }
            
            // Only process lines that start with '>' (OpenVPN commands)
            guard trimmedLine.hasPrefix(">") else { continue }
            
            log.info("Processing management command: '\(trimmedLine)'", category: "server")
            
            // Handle >INFO command
            if trimmedLine.hasPrefix(">INFO") {
                let response = "version 5\r\n"
                sendResponse(response, to: connection)
                log.debug("Sent version info", category: "server")
                continue
            }
            
            // Handle >PK_SIGN command
            if trimmedLine.hasPrefix(">PK_SIGN:") {
                processPKSignCommand(trimmedLine, connection: connection)
                continue
            }
            
            // Handle >NEED-CERTIFICATE command
            if trimmedLine.hasPrefix(">NEED-CERTIFICATE:") {
                processNeedCertificateCommand(trimmedLine, connection: connection)
                continue
            }
            
            // Handle >HOLD command (OpenVPN management interface)
            if trimmedLine.hasPrefix(">HOLD") {
                let response = "SUCCESS: hold release\r\n"
                sendResponse(response, to: connection)
                log.debug("Handled HOLD command", category: "server")
                continue
            }
            
            // Handle >STATE command (OpenVPN status requests)
            if trimmedLine.hasPrefix(">STATE") {
                let response = "SUCCESS: state query\r\n"
                sendResponse(response, to: connection)
                log.debug("Handled STATE command", category: "server")
                continue
            }
            
            // Unknown command
            sendError("Unknown command: \(trimmedLine). Supported: >INFO, >PK_SIGN, >NEED-CERTIFICATE, >HOLD, >STATE", to: connection)
        }
    }
    
    private func processPKSignCommand(_ message: String, connection: NWConnection) {
        // Expected format: >PK_SIGN:<base64_digest>,ECDSA or >PK_SIGN:<base64_digest>
        // The ",ECDSA" suffix is optional (Tunnelblick doesn't include it)
        
        // Remove the >PK_SIGN: prefix
        guard message.hasPrefix(">PK_SIGN:") else {
            sendError("Invalid PK_SIGN format", to: connection)
            return
        }
        
        let commandBody = String(message.dropFirst(9)) // Remove ">PK_SIGN:"
        let components = commandBody.components(separatedBy: ",")
        
        // Accept both formats: with or without ",ECDSA" suffix
        guard !components.isEmpty, !components[0].isEmpty else {
            sendError("Invalid format. Expected: >PK_SIGN:<base64_digest>[,ECDSA]", to: connection)
            return
        }
        
        // If algorithm is specified, verify it's ECDSA (we only support ECDSA)
        if components.count >= 2 && !components[1].isEmpty && components[1] != "ECDSA" {
            sendError("Unsupported algorithm: \(components[1]). Only ECDSA is supported.", to: connection)
            return
        }
        
        let digestBase64 = components[0]
        
        // Convert base64 digest to Data
        guard let digestData = Data(base64Encoded: digestBase64) else {
            sendError("Invalid digest format. Expected base64 string", to: connection)
            return
        }
        
        log.debug("Digest: \(digestBase64) -> \(digestData.count) bytes", category: "server")
        
        // Check if we have an identity with certificate
        guard let core = core else {
            sendError("No core available", to: connection)
            return
        }
        
        do {
            guard try core.hasIdentity() else {
                sendError("No identity found in Secure Enclave", to: connection)
                return
            }
            
            guard try core.hasCertificate() else {
                sendError("No certificate found for identity", to: connection)
                return
            }
            
            log.info("Using single identity for signing", category: "server")
            
            // Sign the digest
            let signature = try core.sign(data: digestData)
            
            // Return signature in new format:
            // pk-sig
            // <base64-encoded DER signature>
            // END
            let base64Signature = signature.base64EncodedString()
            let response = "pk-sig\r\n\(base64Signature)\r\nEND\r\n"
            sendResponse(response, to: connection)
            
            DispatchQueue.main.async {
                self.signCommands += 1
            }
            
            log.debug("Sent signature: \(base64Signature)", category: "server")
            
        } catch {
            sendError("Signing failed: \(error.localizedDescription)", to: connection)
        }
    }
    
    private func processNeedCertificateCommand(_ message: String, connection: NWConnection) {
        // Expected format: >NEED-CERTIFICATE:enclaved or >NEED-CERTIFICATE:enclaved:subject:...
        
        log.info("Processing NEED-CERTIFICATE command: \(message)", category: "server")
        
        // Check if it's requesting enclaved certificate
        guard message.hasPrefix(">NEED-CERTIFICATE:enclaved") else {
            sendError("Only 'enclaved' certificate type is supported", to: connection)
            return
        }
        
        // Check if we have core and identity with certificate
        guard let core = core else {
            sendError("No core available", to: connection)
            return
        }
        
        do {
            guard try core.hasIdentity() else {
                sendError("No identity found in Secure Enclave", to: connection)
                return
            }
            
            guard try core.hasCertificate() else {
                sendError("No certificate found for identity", to: connection)
                return
            }
            
            // Export the certificate in DER format
            guard let certificateData = try core.exportCertificate() else {
                sendError("Failed to export certificate", to: connection)
                return
            }
            
            // Convert to base64 for OpenVPN format
            let base64Certificate = certificateData.base64EncodedString()
            
            // PEM format requires base64 to be wrapped at 64 characters per line
            let wrappedBase64 = base64Certificate.chunked(into: 64).joined(separator: "\r\n")
            
            // Return certificate in OpenVPN format:
            // certificate
            // -----BEGIN CERTIFICATE-----
            // <base64-encoded DER certificate>
            // -----END CERTIFICATE-----
            // END
            let response = "certificate\r\n-----BEGIN CERTIFICATE-----\r\n\(wrappedBase64)\r\n-----END CERTIFICATE-----\r\nEND\r\n"
            sendResponse(response, to: connection)
            
            DispatchQueue.main.async {
                self.certificateCommands += 1
            }
            
            log.debug("Sent certificate: \(base64Certificate.prefix(50))...", category: "server")
            
        } catch {
            sendError("Certificate export failed: \(error.localizedDescription)", to: connection)
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
    
    private func sendError(_ error: String, to connection: NWConnection) {
        let response = "ERROR: \(error)\r\n"
        log.error("Sending error response: \(error)", category: "server")
        sendResponse(response, to: connection)
        DispatchQueue.main.async {
            self.errorCount += 1
        }
        // Keep connection alive after sending error
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