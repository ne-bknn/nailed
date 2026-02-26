// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Pure protocol handler for the OpenVPN management interface.
/// Parses `>`-prefixed command lines and returns wire-format response strings.
/// Has no network or UI dependencies — fully unit-testable.
struct ManagementCommandHandler {
    private let core: any NailedCoreProtocol
    private let log = NailedLogger.shared

    init(core: any NailedCoreProtocol) {
        self.core = core
    }

    /// Process a raw UTF-8 message (possibly multi-line) and return one response
    /// string per recognized `>`-prefixed command.
    func handleMessage(_ message: String) -> [String] {
        var responses: [String] = []

        for line in message.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.hasPrefix(">") else { continue }

            log.info("Processing management command: '\(trimmed)'", category: "server")
            responses.append(handleCommand(trimmed))
        }

        return responses
    }

    // MARK: - Command dispatch

    private func handleCommand(_ command: String) -> String {
        if command.hasPrefix(">INFO") {
            return handleInfo()
        }
        if command.hasPrefix(">PK_SIGN:") {
            return handlePKSign(command)
        }
        if command.hasPrefix(">NEED-CERTIFICATE:") {
            return handleNeedCertificate(command)
        }
        if command.hasPrefix(">HOLD") {
            return handleHold()
        }
        if command.hasPrefix(">STATE") {
            return handleState()
        }
        return errorResponse("Unknown command: \(command). Supported: >INFO, >PK_SIGN, >NEED-CERTIFICATE, >HOLD, >STATE")
    }

    // MARK: - Individual handlers

    private func handleInfo() -> String {
        log.debug("Sent version info", category: "server")
        return "version 5\r\n"
    }

    private func handleHold() -> String {
        log.debug("Handled HOLD command", category: "server")
        return "SUCCESS: hold release\r\n"
    }

    private func handleState() -> String {
        log.debug("Handled STATE command", category: "server")
        return "SUCCESS: state query\r\n"
    }

    private func handlePKSign(_ message: String) -> String {
        let commandBody = String(message.dropFirst(9)) // ">PK_SIGN:"
        let components = commandBody.components(separatedBy: ",")

        guard !components.isEmpty, !components[0].isEmpty else {
            return errorResponse("Invalid format. Expected: >PK_SIGN:<base64_digest>[,ECDSA]")
        }

        if components.count >= 2 && !components[1].isEmpty && components[1] != "ECDSA" {
            return errorResponse("Unsupported algorithm: \(components[1]). Only ECDSA is supported.")
        }

        guard let digestData = Data(base64Encoded: components[0]) else {
            return errorResponse("Invalid digest format. Expected base64 string")
        }

        log.debug("Digest: \(components[0]) -> \(digestData.count) bytes", category: "server")

        do {
            guard try core.hasIdentity() else {
                return errorResponse("No identity found in Secure Enclave")
            }
            guard try core.hasCertificate() else {
                return errorResponse("No certificate found for identity")
            }

            log.info("Using single identity for signing", category: "server")
            let signature = try core.sign(data: digestData)
            let base64Signature = signature.base64EncodedString()
            log.debug("Sent signature: \(base64Signature)", category: "server")
            return "pk-sig\r\n\(base64Signature)\r\nEND\r\n"
        } catch {
            return errorResponse("Signing failed: \(error.localizedDescription)")
        }
    }

    private func handleNeedCertificate(_ message: String) -> String {
        log.info("Processing NEED-CERTIFICATE command: \(message)", category: "server")

        guard message.hasPrefix(">NEED-CERTIFICATE:enclaved") else {
            return errorResponse("Only 'enclaved' certificate type is supported")
        }

        do {
            guard try core.hasIdentity() else {
                return errorResponse("No identity found in Secure Enclave")
            }
            guard try core.hasCertificate() else {
                return errorResponse("No certificate found for identity")
            }
            guard let certificateData = try core.exportCertificate() else {
                return errorResponse("Failed to export certificate")
            }

            let base64Certificate = certificateData.base64EncodedString()
            let wrappedBase64 = base64Certificate.chunked(into: 64).joined(separator: "\r\n")
            log.debug("Sent certificate: \(base64Certificate.prefix(50))...", category: "server")
            return "certificate\r\n-----BEGIN CERTIFICATE-----\r\n\(wrappedBase64)\r\n-----END CERTIFICATE-----\r\nEND\r\n"
        } catch {
            return errorResponse("Certificate export failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Helpers

    private func errorResponse(_ message: String) -> String {
        log.error("Sending error response: \(message)", category: "server")
        return "ERROR: \(message)\r\n"
    }
}
