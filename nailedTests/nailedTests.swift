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
