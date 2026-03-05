// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Per-connection session for the custom NDJSON protocol between
/// the PKCS#11 module and nailed.
class Session {
    private let core: any NailedCoreProtocol
    private let log: any LoggerProtocol
    private var pin: Data?

    init(core: any NailedCoreProtocol, logger: any LoggerProtocol = NailedLogger.shared) {
        self.core = core
        self.log = logger
    }

    // MARK: - Wire types

    private struct Request: Decodable {
        let cmd: String
        var pin: String?
        var digest: String?
        var algorithm: String?
    }

    private struct Response: Encodable {
        let ok: Bool
        var error: String?
        var version: String?
        var `protocol`: Int?
        var type: String?
        var certificate: String?
        var signature: String?
    }

    // MARK: - Public entry point

    /// Process a single NDJSON line (UTF-8 data without trailing newline)
    /// and return a JSON response line (without trailing newline).
    func handleRequest(_ data: Data) -> Data {
        let response: Response
        do {
            let request = try JSONDecoder().decode(Request.self, from: data)
            log.info("Session handling cmd=\(request.cmd)", category: "session")
            response = try dispatch(request)
        } catch let error as DecodingError {
            log.error("Failed to decode request: \(error)", category: "session")
            response = Response(ok: false, error: "invalid request JSON")
        } catch {
            response = Response(ok: false, error: error.localizedDescription)
        }

        do {
            return try JSONEncoder().encode(response)
        } catch {
            log.error("Failed to encode response: \(error)", category: "session")
            return Data(#"{"ok":false,"error":"internal encoding error"}"#.utf8)
        }
    }

    // MARK: - Dispatch

    private func dispatch(_ req: Request) throws -> Response {
        switch req.cmd {
        case "VERSION":     return handleVersion()
        case "KEY_TYPE":    return try handleKeyType()
        case "LOGIN":       return handleLogin(req)
        case "CERTIFICATE": return try handleCertificate()
        case "SIGN":        return try handleSign(req)
        default:
            return Response(ok: false, error: "unknown command: \(req.cmd)")
        }
    }

    // MARK: - Handlers

    private func handleVersion() -> Response {
        Response(ok: true, version: AppVersion.version, protocol: 1)
    }

    private func handleKeyType() throws -> Response {
        guard try core.hasIdentity() else {
            return Response(ok: false, error: "no identity found")
        }
        let type = try core.protectionType
        return Response(ok: true, type: type.rawValue)
    }

    private func handleLogin(_ req: Request) -> Response {
        guard let pinString = req.pin, !pinString.isEmpty else {
            return Response(ok: false, error: "missing or empty pin")
        }
        pin = Data(pinString.utf8)
        log.info("PIN stored for session", category: "session")
        return Response(ok: true)
    }

    private func handleCertificate() throws -> Response {
        guard try core.hasIdentity() else {
            return Response(ok: false, error: "no identity found")
        }
        guard try core.hasCertificate() else {
            return Response(ok: false, error: "no certificate found")
        }
        guard let certData = try core.exportCertificate() else {
            return Response(ok: false, error: "failed to export certificate")
        }
        return Response(ok: true, certificate: certData.base64EncodedString())
    }

    private func handleSign(_ req: Request) throws -> Response {
        guard let digestB64 = req.digest, !digestB64.isEmpty else {
            return Response(ok: false, error: "missing digest")
        }
        guard let digestData = Data(base64Encoded: digestB64) else {
            return Response(ok: false, error: "invalid base64 digest")
        }

        if let algo = req.algorithm, !algo.isEmpty, algo != "ECDSA" {
            return Response(ok: false, error: "unsupported algorithm: \(algo). Only ECDSA is supported.")
        }

        guard try core.hasIdentity() else {
            return Response(ok: false, error: "no identity found")
        }

        let signature = try core.sign(data: digestData, password: pin)
        return Response(ok: true, signature: signature.base64EncodedString())
    }
}
