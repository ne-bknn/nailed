// SPDX-License-Identifier: Apache-2.0
import Testing
import Foundation
@testable import nailed

// MARK: - Mock Logger

final class MockLogger: LoggerProtocol {
    var entries: [(level: String, category: String, message: String)] = []

    func debug(_ message: String, category: String) { entries.append(("debug", category, message)) }
    func info(_ message: String, category: String) { entries.append(("info", category, message)) }
    func warning(_ message: String, category: String) { entries.append(("warning", category, message)) }
    func error(_ message: String, category: String) { entries.append(("error", category, message)) }
}

// MARK: - Mock Core

final class MockNailedCore: NailedCoreProtocol {
    var identityExists = false
    var certificateExists = false
    var stubbedCertificateInfo: CertificateInfo? = nil
    var signResult: Data = Data()
    var exportedCertificate: Data? = nil
    var exportedPublicKey: Data? = nil
    var generatedCSR: Data = Data()
    var stubbedProtectionType: KeyProtectionType = .userPresence

    var generateIdentityCalled = false
    var generateIdentityProtectionType: KeyProtectionType?
    var deleteIdentityCalled = false
    var importedCertificateData: Data? = nil
    var lastSignPassword: Data? = nil

    func hasIdentity() throws -> Bool { identityExists }
    func generateIdentity(protectionType: KeyProtectionType) throws {
        generateIdentityCalled = true
        generateIdentityProtectionType = protectionType
    }
    func hasCertificate() throws -> Bool { certificateExists }
    func getCertificateInfo() throws -> CertificateInfo? { stubbedCertificateInfo }
    func generateCSR(commonName: String) throws -> Data { generatedCSR }
    func importCertificate(certificateData: Data) throws {
        importedCertificateData = certificateData
    }
    func exportCertificate() throws -> Data? { exportedCertificate }
    func exportPublicKey() throws -> Data? { exportedPublicKey }
    func sign(data: Data, password: Data?) throws -> Data {
        lastSignPassword = password
        return signResult
    }
    func deleteIdentity() throws { deleteIdentityCalled = true }
    var protectionType: KeyProtectionType {
        get throws { stubbedProtectionType }
    }
}

struct nailedTests {
    @Test func mockConformsToProtocol() async throws {
        let mock = MockNailedCore()
        let core: any NailedCoreProtocol = mock

        #expect(try core.hasIdentity() == false)

        mock.identityExists = true
        #expect(try core.hasIdentity() == true)

        try core.generateIdentity(protectionType: .userPresence)
        #expect(mock.generateIdentityCalled)
        #expect(mock.generateIdentityProtectionType == .userPresence)

        try core.deleteIdentity()
        #expect(mock.deleteIdentityCalled)

        let testData = Data([0x01, 0x02, 0x03])
        mock.signResult = testData
        #expect(try core.sign(data: Data(), password: nil) == testData)
    }
}

// MARK: - CLI Invocation Detection Tests

struct CLIInvocationTests {

    @Test func knownSubcommandIsCliInvocation() {
        #expect(NailedCommand.isCliInvocation("status"))
        #expect(NailedCommand.isCliInvocation("generate-identity"))
        #expect(NailedCommand.isCliInvocation("generate-csr"))
        #expect(NailedCommand.isCliInvocation("import-certificate"))
        #expect(NailedCommand.isCliInvocation("export-certificate"))
        #expect(NailedCommand.isCliInvocation("delete-identity"))
        #expect(NailedCommand.isCliInvocation("enable-login-item"))
        #expect(NailedCommand.isCliInvocation("disable-login-item"))
    }

    @Test func helpFlagsAreCliInvocations() {
        #expect(NailedCommand.isCliInvocation("help"))
        #expect(NailedCommand.isCliInvocation("--help"))
        #expect(NailedCommand.isCliInvocation("-h"))
        #expect(NailedCommand.isCliInvocation("--version"))
    }

    @Test func unknownArgIsNotCliInvocation() {
        #expect(!NailedCommand.isCliInvocation("--unknown-flag"))
    }

    @Test func daemonIsNotCliInvocation() {
        #expect(!NailedCommand.isCliInvocation("daemon"))
    }
}

// MARK: - Session Tests

struct SessionTests {

    private func makeSession(
        identityExists: Bool = true,
        certificateExists: Bool = true,
        signResult: Data = Data(repeating: 0xAB, count: 8),
        exportedCertificate: Data? = Data(repeating: 0xCD, count: 16),
        protectionType: KeyProtectionType = .userPresence
    ) -> (Session, MockNailedCore) {
        let mock = MockNailedCore()
        mock.identityExists = identityExists
        mock.certificateExists = certificateExists
        mock.signResult = signResult
        mock.exportedCertificate = exportedCertificate
        mock.stubbedProtectionType = protectionType
        return (Session(core: mock, logger: MockLogger()), mock)
    }

    private func request(_ json: String, session: Session) -> [String: Any] {
        let responseData = session.handleRequest(Data(json.utf8))
        return (try? JSONSerialization.jsonObject(with: responseData) as? [String: Any]) ?? [:]
    }

    // MARK: - VERSION

    @Test func versionReturnsOk() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"VERSION"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["protocol"] as? Int == 1)
        #expect(resp["version"] as? String != nil)
    }

    // MARK: - KEY_TYPE

    @Test func keyTypeReturnsUserPresence() {
        let (session, _) = makeSession(protectionType: .userPresence)
        let resp = request(#"{"cmd":"KEY_TYPE"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["type"] as? String == "user-presence")
    }

    @Test func keyTypeReturnsApplicationPassword() {
        let (session, _) = makeSession(protectionType: .applicationPassword)
        let resp = request(#"{"cmd":"KEY_TYPE"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["type"] as? String == "application-password")
    }

    @Test func keyTypeNoIdentity() {
        let (session, _) = makeSession(identityExists: false)
        let resp = request(#"{"cmd":"KEY_TYPE"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("identity") == true)
    }

    // MARK: - LOGIN

    @Test func loginStoresPin() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"LOGIN","pin":"s3cret"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
    }

    @Test func loginEmptyPinFails() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"LOGIN","pin":""}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
    }

    @Test func loginMissingPinFails() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"LOGIN"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
    }

    // MARK: - CERTIFICATE

    @Test func certificateReturnsBase64() {
        let certData = Data(repeating: 0xEE, count: 100)
        let (session, _) = makeSession(exportedCertificate: certData)
        let resp = request(#"{"cmd":"CERTIFICATE"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["certificate"] as? String == certData.base64EncodedString())
    }

    @Test func certificateNoIdentity() {
        let (session, _) = makeSession(identityExists: false)
        let resp = request(#"{"cmd":"CERTIFICATE"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("identity") == true)
    }

    @Test func certificateNoCertificate() {
        let (session, _) = makeSession(certificateExists: false)
        let resp = request(#"{"cmd":"CERTIFICATE"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("certificate") == true)
    }

    @Test func certificateExportReturnsNil() {
        let (session, _) = makeSession(exportedCertificate: nil)
        let resp = request(#"{"cmd":"CERTIFICATE"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("export") == true)
    }

    // MARK: - SIGN

    @Test func signReturnsSignature() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0x01, 0x02, 0x03])
        let (session, _) = makeSession(signResult: sig)
        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())","algorithm":"ECDSA"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["signature"] as? String == sig.base64EncodedString())
    }

    @Test func signWithoutAlgorithm() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0x01, 0x02, 0x03])
        let (session, _) = makeSession(signResult: sig)
        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())"}"#, session: session)
        #expect(resp["ok"] as? Bool == true)
        #expect(resp["signature"] as? String == sig.base64EncodedString())
    }

    @Test func signUnsupportedAlgorithm() {
        let digest = Data(repeating: 0x42, count: 32)
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())","algorithm":"RSA"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("RSA") == true)
    }

    @Test func signMissingDigest() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"SIGN"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("digest") == true)
    }

    @Test func signInvalidBase64() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"SIGN","digest":"not-valid!!!"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("base64") == true)
    }

    @Test func signNoIdentity() {
        let digest = Data(repeating: 0x42, count: 32)
        let (session, _) = makeSession(identityExists: false)
        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("identity") == true)
    }

    // MARK: - PIN flow

    @Test func signAfterLoginPassesPinToCore() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0xAA])
        let (session, mock) = makeSession(signResult: sig)

        _ = request(#"{"cmd":"LOGIN","pin":"myPin"}"#, session: session)
        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())"}"#, session: session)

        #expect(resp["ok"] as? Bool == true)
        #expect(mock.lastSignPassword == Data("myPin".utf8))
    }

    @Test func signWithoutLoginPassesNilPassword() {
        let digest = Data(repeating: 0x42, count: 32)
        let sig = Data([0xBB])
        let (session, mock) = makeSession(signResult: sig)

        let resp = request(#"{"cmd":"SIGN","digest":"\#(digest.base64EncodedString())"}"#, session: session)

        #expect(resp["ok"] as? Bool == true)
        #expect(mock.lastSignPassword == nil)
    }

    // MARK: - Unknown command / invalid JSON

    @Test func unknownCommandReturnsError() {
        let (session, _) = makeSession()
        let resp = request(#"{"cmd":"FOO"}"#, session: session)
        #expect(resp["ok"] as? Bool == false)
        #expect((resp["error"] as? String)?.contains("FOO") == true)
    }

    @Test func invalidJsonReturnsError() {
        let (session, _) = makeSession()
        let resp = request("not json at all", session: session)
        #expect(resp["ok"] as? Bool == false)
    }
}

// MARK: - UnixSigningServer Tests

struct UnixSigningServerTests {

    @Test func initialStatusIsNotRunning() {
        let server = UnixSigningServer(core: nil, logger: MockLogger())
        #expect(server.status.isRunning == false)
        #expect(server.status.statusMessage == "Server stopped")
        #expect(server.status.errorMessage == "")
    }

    @Test func defaultSocketPath() {
        let server = UnixSigningServer(core: nil, logger: MockLogger())
        #expect(server.socketPath == "/tmp/nailed_signing.sock")
    }

    @Test func customSocketPath() {
        let server = UnixSigningServer(core: nil, socketPath: "/tmp/custom.sock", logger: MockLogger())
        #expect(server.socketPath == "/tmp/custom.sock")
    }

    @Test func stopServerOnIdleIsNoOp() {
        var callbackCount = 0
        let server = UnixSigningServer(core: nil, logger: MockLogger())
        server.onStatusChange = { _ in callbackCount += 1 }

        server.stopServer()

        #expect(server.status.isRunning == false)
        #expect(server.status.statusMessage == "Management server stopped")
        #expect(callbackCount == 1)
    }

    @Test func callbackReceivesStatusOnStop() {
        var receivedStatus: ServerStatus?
        let server = UnixSigningServer(core: nil, logger: MockLogger())
        server.onStatusChange = { status in receivedStatus = status }

        server.stopServer()

        #expect(receivedStatus != nil)
        #expect(receivedStatus?.isRunning == false)
        #expect(receivedStatus?.statusMessage == "Management server stopped")
        #expect(receivedStatus?.errorMessage == "")
    }
}
