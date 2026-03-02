// SPDX-License-Identifier: Apache-2.0
import Testing
import Foundation
@testable import nailed

final class MockNailedCore: NailedCoreProtocol {
    var identityExists = false
    var certificateExists = false
    var stubbedCertificateInfo: CertificateInfo? = nil
    var signResult: Data = Data()
    var exportedCertificate: Data? = nil
    var exportedPublicKey: Data? = nil
    var generatedCSR: Data = Data()

    var generateIdentityCalled = false
    var deleteIdentityCalled = false
    var importedCertificateData: Data? = nil

    func hasIdentity() throws -> Bool { identityExists }
    func generateIdentity() throws { generateIdentityCalled = true }
    func hasCertificate() throws -> Bool { certificateExists }
    func getCertificateInfo() throws -> CertificateInfo? { stubbedCertificateInfo }
    func generateCSR(commonName: String) throws -> Data { generatedCSR }
    func importCertificate(certificateData: Data) throws {
        importedCertificateData = certificateData
    }
    func exportCertificate() throws -> Data? { exportedCertificate }
    func exportPublicKey() throws -> Data? { exportedPublicKey }
    func sign(data: Data) throws -> Data { signResult }
    func deleteIdentity() throws { deleteIdentityCalled = true }
}

struct nailedTests {
    @Test func mockConformsToProtocol() async throws {
        let mock = MockNailedCore()
        let core: any NailedCoreProtocol = mock

        #expect(try core.hasIdentity() == false)

        mock.identityExists = true
        #expect(try core.hasIdentity() == true)

        try core.generateIdentity()
        #expect(mock.generateIdentityCalled)

        try core.deleteIdentity()
        #expect(mock.deleteIdentityCalled)

        let testData = Data([0x01, 0x02, 0x03])
        mock.signResult = testData
        #expect(try core.sign(data: Data()) == testData)
    }
}

// MARK: - RuntimeMode Tests

struct RuntimeModeTests {

    @Test func defaultIsApp() {
        let mode = RuntimeMode.resolve(from: [])
        guard case .app = mode else { return #expect(Bool(false)) }
    }

    @Test func daemonMode() {
        let mode = RuntimeMode.resolve(from: ["daemon"])
        guard case .daemon = mode else { return #expect(Bool(false)) }
    }

    @Test func cliCommand() {
        let mode = RuntimeMode.resolve(from: ["status"])
        guard case .cli(let cmd, _) = mode else { return #expect(Bool(false)) }
        #expect(cmd == "status")
    }

    @Test func cliCommandPreservesFullArgs() {
        let mode = RuntimeMode.resolve(from: ["generate-csr", "My Name", "-o", "out.csr"])
        guard case .cli(let cmd, let all) = mode else { return #expect(Bool(false)) }
        #expect(cmd == "generate-csr")
        #expect(all == ["generate-csr", "My Name", "-o", "out.csr"])
    }

    @Test func unknownArgFallsToApp() {
        let mode = RuntimeMode.resolve(from: ["--unknown-flag"])
        guard case .app = mode else { return #expect(Bool(false)) }
    }
}

// MARK: - ManagementCommandHandler Tests

struct ManagementCommandHandlerTests {

    private func makeHandler(
        identityExists: Bool = true,
        certificateExists: Bool = true,
        signResult: Data = Data(repeating: 0xAB, count: 8),
        exportedCertificate: Data? = Data(repeating: 0xCD, count: 16)
    ) -> (ManagementCommandHandler, MockNailedCore) {
        let mock = MockNailedCore()
        mock.identityExists = identityExists
        mock.certificateExists = certificateExists
        mock.signResult = signResult
        mock.exportedCertificate = exportedCertificate
        return (ManagementCommandHandler(core: mock), mock)
    }

    // MARK: - Simple commands

    @Test func infoReturnsVersion() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">INFO")
        #expect(results == ["version 5\r\n"])
    }

    @Test func holdReturnsSuccess() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">HOLD")
        #expect(results == ["SUCCESS: hold release\r\n"])
    }

    @Test func stateReturnsSuccess() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">STATE")
        #expect(results == ["SUCCESS: state query\r\n"])
    }

    // MARK: - Unknown / ignored input

    @Test func unknownCommandReturnsError() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">FOO")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains(">FOO"))
    }

    @Test func linesWithoutPrefixAreSkipped() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage("plain text\nno prefix here")
        #expect(results.isEmpty)
    }

    @Test func emptyMessageReturnsNothing() {
        let (handler, _) = makeHandler()
        #expect(handler.handleMessage("").isEmpty)
        #expect(handler.handleMessage("   ").isEmpty)
        #expect(handler.handleMessage("\n\n").isEmpty)
    }

    // MARK: - Multi-line

    @Test func multiLineProducesMultipleResponses() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">INFO\n>HOLD\n>STATE")
        #expect(results.count == 3)
        #expect(results[0] == "version 5\r\n")
        #expect(results[1] == "SUCCESS: hold release\r\n")
        #expect(results[2] == "SUCCESS: state query\r\n")
    }

    @Test func multiLineMixedWithNonCommands() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage("hello\n>INFO\nignored\n>HOLD")
        #expect(results.count == 2)
    }

    // MARK: - PK_SIGN

    @Test func pkSignWithECDSASuffix() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0x01, 0x02, 0x03])
        let (handler, _) = makeHandler(signResult: sig)

        let results = handler.handleMessage(">PK_SIGN:\(digest.base64EncodedString()),ECDSA")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("pk-sig\r\n"))
        #expect(results[0].hasSuffix("END\r\n"))
        #expect(results[0].contains(sig.base64EncodedString()))
    }

    @Test func pkSignWithoutAlgorithmSuffix() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0x01, 0x02, 0x03])
        let (handler, _) = makeHandler(signResult: sig)

        let results = handler.handleMessage(">PK_SIGN:\(digest.base64EncodedString())")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("pk-sig\r\n"))
    }

    @Test func pkSignInvalidBase64() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">PK_SIGN:not-valid-base64!!!")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("base64"))
    }

    @Test func pkSignEmptyDigest() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">PK_SIGN:")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
    }

    @Test func pkSignUnsupportedAlgorithm() {
        let digest = Data(repeating: 0x42, count: 32)
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">PK_SIGN:\(digest.base64EncodedString()),RSA")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("RSA"))
    }

    @Test func pkSignNoIdentity() {
        let digest = Data(repeating: 0x42, count: 32)
        let (handler, _) = makeHandler(identityExists: false)
        let results = handler.handleMessage(">PK_SIGN:\(digest.base64EncodedString()),ECDSA")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("identity"))
    }

    @Test func pkSignNoCertificate() {
        let digest = Data(repeating: 0x42, count: 32)
        let (handler, _) = makeHandler(certificateExists: false)
        let results = handler.handleMessage(">PK_SIGN:\(digest.base64EncodedString()),ECDSA")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("certificate"))
    }

    // MARK: - NEED-CERTIFICATE

    @Test func needCertificateEnclaved() {
        let certData = Data(repeating: 0xEE, count: 100)
        let (handler, _) = makeHandler(exportedCertificate: certData)

        let results = handler.handleMessage(">NEED-CERTIFICATE:enclaved")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("certificate\r\n"))
        #expect(results[0].contains("-----BEGIN CERTIFICATE-----"))
        #expect(results[0].contains("-----END CERTIFICATE-----"))
        #expect(results[0].hasSuffix("END\r\n"))
    }

    @Test func needCertificateNonEnclavedType() {
        let (handler, _) = makeHandler()
        let results = handler.handleMessage(">NEED-CERTIFICATE:other")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("enclaved"))
    }

    @Test func needCertificateNoIdentity() {
        let (handler, _) = makeHandler(identityExists: false)
        let results = handler.handleMessage(">NEED-CERTIFICATE:enclaved")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("identity"))
    }

    @Test func needCertificateNoCertificate() {
        let (handler, _) = makeHandler(certificateExists: false)
        let results = handler.handleMessage(">NEED-CERTIFICATE:enclaved")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("certificate"))
    }

    @Test func needCertificateExportReturnsNil() {
        let (handler, _) = makeHandler(exportedCertificate: nil)
        let results = handler.handleMessage(">NEED-CERTIFICATE:enclaved")
        #expect(results.count == 1)
        #expect(results[0].hasPrefix("ERROR:"))
        #expect(results[0].contains("export"))
    }
}

// MARK: - UnixSigningServer Tests

struct UnixSigningServerTests {

    @Test func initialStatusIsNotRunning() {
        let server = UnixSigningServer(core: nil)
        #expect(server.status.isRunning == false)
        #expect(server.status.statusMessage == "Server stopped")
        #expect(server.status.errorMessage == "")
    }

    @Test func defaultSocketPath() {
        let server = UnixSigningServer(core: nil)
        #expect(server.socketPath == "/tmp/nailed_signing.sock")
    }

    @Test func customSocketPath() {
        let server = UnixSigningServer(core: nil, socketPath: "/tmp/custom.sock")
        #expect(server.socketPath == "/tmp/custom.sock")
    }

    @Test func stopServerOnIdleIsNoOp() {
        var callbackCount = 0
        let server = UnixSigningServer(core: nil)
        server.onStatusChange = { _ in callbackCount += 1 }

        server.stopServer()

        #expect(server.status.isRunning == false)
        #expect(server.status.statusMessage == "Management server stopped")
        #expect(callbackCount == 1)
    }

    @Test func callbackReceivesStatusOnStop() {
        var receivedStatus: ServerStatus?
        let server = UnixSigningServer(core: nil)
        server.onStatusChange = { status in receivedStatus = status }

        server.stopServer()

        #expect(receivedStatus != nil)
        #expect(receivedStatus?.isRunning == false)
        #expect(receivedStatus?.statusMessage == "Management server stopped")
        #expect(receivedStatus?.errorMessage == "")
    }
}
