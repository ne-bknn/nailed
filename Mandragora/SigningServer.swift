import Foundation
import Network

class UnixSigningServer: ObservableObject {
    @Published var isRunning = false
    @Published var socketPath: String = "/tmp/mandragora_signing.sock"
    @Published var statusMessage = "Server stopped"
    @Published var errorMessage = ""
    
    private var listener: NWListener?
    private var core: MandragoraCore?
    private var activeConnections: [NWConnection] = []
    
    init(core: MandragoraCore?) {
        self.core = core
    }
    
    func updateCore(_ core: MandragoraCore?) {
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
        print("New management connection received")
        activeConnections.append(connection)
        
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                print("Management connection ready")
                self?.receiveMessage(from: connection)
            case .failed(let error):
                print("Management connection failed: \(error)")
                self?.removeConnection(connection)
            case .cancelled:
                print("Management connection cancelled")
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
                print("Receive error: \(error)")
                self?.removeConnection(connection)
                return
            }
            
            if let data = data, !data.isEmpty {
                if let message = String(data: data, encoding: .utf8) {
                    print("Received management message: '\(message)'")
                    self?.processMessage(message.trimmingCharacters(in: .whitespacesAndNewlines), connection: connection)
                } else {
                    print("Failed to decode message as UTF-8")
                    self?.sendError("Invalid UTF-8 encoding", to: connection)
                }
            }
            
            if isComplete {
                print("Management connection closed by client")
                self?.removeConnection(connection)
            } else {
                // Continue listening for more messages
                self?.receiveMessage(from: connection)
            }
        }
    }
    
    private func processMessage(_ message: String, connection: NWConnection) {
        print("Processing management message: '\(message)'")
        
        // Split message by lines and process each command that starts with '>'
        let lines = message.components(separatedBy: .newlines)
        
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            
            // Skip empty lines
            guard !trimmedLine.isEmpty else { continue }
            
            // Only process lines that start with '>' (OpenVPN commands)
            guard trimmedLine.hasPrefix(">") else { continue }
            
            print("Processing management command: '\(trimmedLine)'")
            
            // Handle >INFO command
            if trimmedLine.hasPrefix(">INFO") {
                let response = "version 5\r\n"
                sendResponse(response, to: connection)
                print("Sent version info")
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
                print("Handled HOLD command")
                continue
            }
            
            // Handle >STATE command (OpenVPN status requests)
            if trimmedLine.hasPrefix(">STATE") {
                let response = "SUCCESS: state query\r\n"
                sendResponse(response, to: connection)
                print("Handled STATE command")
                continue
            }
            
            // Unknown command
            sendError("Unknown command: \(trimmedLine). Supported: >INFO, >PK_SIGN, >NEED-CERTIFICATE, >HOLD, >STATE", to: connection)
        }
    }
    
    private func processPKSignCommand(_ message: String, connection: NWConnection) {
        // Expected format: >PK_SIGN:WXRmZWN0ZWRTaWduaW5nRGF0YQ==,ECDSA
        
        // Remove the >PK_SIGN: prefix
        guard message.hasPrefix(">PK_SIGN:") else {
            sendError("Invalid PK_SIGN format", to: connection)
            return
        }
        
        let commandBody = String(message.dropFirst(9)) // Remove ">PK_SIGN:"
        let components = commandBody.components(separatedBy: ",")
        
        guard components.count == 2,
              components[1] == "ECDSA" else {
            sendError("Invalid format. Expected: >PK_SIGN:<base64_digest>,ECDSA", to: connection)
            return
        }
        
        let digestBase64 = components[0]
        
        // Convert base64 digest to Data
        guard let digestData = Data(base64Encoded: digestBase64) else {
            sendError("Invalid digest format. Expected base64 string", to: connection)
            return
        }
        
        print("Digest: \(digestBase64) -> \(digestData.count) bytes")
        
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
            
            print("Using single identity for signing")
            
            // Sign the digest
            let signature = try core.sign(data: digestData)
            
            // Return signature in new format:
            // pk-sig
            // <base64-encoded DER signature>
            // END
            let base64Signature = signature.base64EncodedString()
            let response = "pk-sig\r\n\(base64Signature)\r\nEND\r\n"
            sendResponse(response, to: connection)
            
            print("Sent signature: \(base64Signature)")
            
        } catch {
            sendError("Signing failed: \(error.localizedDescription)", to: connection)
        }
    }
    
    private func processNeedCertificateCommand(_ message: String, connection: NWConnection) {
        // Expected format: >NEED-CERTIFICATE:enclaved or >NEED-CERTIFICATE:enclaved:subject:...
        
        print("Processing NEED-CERTIFICATE command: \(message)")
        
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
            
            // Return certificate in OpenVPN format:
            // certificate
            // -----BEGIN CERTIFICATE-----
            // <base64-encoded DER certificate>
            // -----END CERTIFICATE-----
            // END
            let response = "certificate\r\n-----BEGIN CERTIFICATE-----\r\n\(base64Certificate)\r\n-----END CERTIFICATE-----\r\nEND\r\n"
            sendResponse(response, to: connection)
            
            print("Sent certificate: \(base64Certificate.prefix(50))...")
            
        } catch {
            sendError("Certificate export failed: \(error.localizedDescription)", to: connection)
        }
    }
    
    private func sendResponse(_ response: String, to connection: NWConnection) {
        let data = response.data(using: .utf8)!
        connection.send(content: data, completion: .contentProcessed { error in
            if let error = error {
                print("Send error: \(error)")
                // Don't cancel connection on send errors, just log and continue
            } else {
                print("Response sent successfully, waiting for more requests")
            }
            // Keep connection alive for more requests
        })
    }
    
    private func sendError(_ error: String, to connection: NWConnection) {
        let response = "ERROR: \(error)\r\n"
        print("Sending error: \(error)")
        sendResponse(response, to: connection)
        // Keep connection alive after sending error
    }
}