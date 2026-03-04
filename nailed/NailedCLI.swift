// SPDX-License-Identifier: Apache-2.0

import Foundation
import ArgumentParser
import ServiceManagement

struct NailedCommand: ParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "nailed",
        abstract: "Secure Enclave identity manager",
        version: AppVersion.version,
        subcommands: [
            Status.self,
            GenerateIdentity.self,
            GenerateCSR.self,
            ImportCertificate.self,
            ExportCertificate.self,
            DeleteIdentity.self,
            EnableLoginItem.self,
            DisableLoginItem.self,
        ],
        helpNames: [.short, .long]
    )

    /// Returns true when the first CLI argument matches a known subcommand
    /// or a built-in flag like --help / --version, so that `main.swift` can
    /// distinguish CLI invocations from a bare GUI launch.
    static func isCliInvocation(_ arg: String) -> Bool {
        let subcommandNames = configuration.subcommands.map {
            $0._commandName
        }
        return subcommandNames.contains(arg)
            || ["help", "--help", "-h", "--version"].contains(arg)
    }
}

// MARK: - Helpers

private func initCore() throws -> NailedCore {
    do {
        return try NailedCore(logger: NailedLogger.shared)
    } catch {
        throw ValidationError("failed to initialize: \(error.localizedDescription)")
    }
}

private func printStderr(_ message: String, terminator: String = "\n") {
    FileHandle.standardError.write(Data((message + terminator).utf8))
}

// MARK: - status

extension NailedCommand {

    struct Status: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show identity and certificate status"
        )

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: status", category: "cli")

            guard try core.hasIdentity() else {
                print("Identity: not found")
                print("  No Secure Enclave key pair exists. Run 'generate-identity' to create one.")
                return
            }

            print("Identity: present")
            print("  Private key available in Secure Enclave")

            guard try core.hasCertificate() else {
                print("  Certificate: not imported")
                print("  Generate a CSR with 'generate-csr' and import the signed certificate with 'import-certificate'.")
                return
            }

            print("  Certificate: imported")

            if let info = try core.getCertificateInfo() {
                if let cn = info.commonName {
                    print("    Subject CN:  \(cn)")
                }
                if let issuer = info.issuerCommonName {
                    print("    Issuer CN:   \(issuer)")
                }

                let df = DateFormatter()
                df.dateStyle = .medium
                df.timeStyle = .short
                print("    Not before:  \(df.string(from: info.notValidBefore))")
                print("    Not after:   \(df.string(from: info.notValidAfter))")
                print("    Valid now:   \(info.isValid ? "yes" : "NO")")
            }
        }
    }
}

// MARK: - generate-identity

extension NailedCommand {

    struct GenerateIdentity: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "generate-identity",
            abstract: "Generate a new Secure Enclave key pair"
        )

        @Flag(name: [.short, .long], help: "Skip confirmation when replacing an existing identity.")
        var force = false

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: generate-identity", category: "cli")

            if try core.hasIdentity() {
                if !force {
                    printStderr("An existing identity will be permanently destroyed and replaced.")
                    printStderr("Type 'yes' to confirm: ", terminator: "")
                    guard let response = readLine(), response.lowercased() == "yes" else {
                        printStderr("Aborted.")
                        throw ExitCode(1)
                    }
                }
            }

            try core.generateIdentity()
            print("Identity generated successfully.")
            print("  A new EC P-256 key pair has been created in the Secure Enclave.")
            print("  Next step: generate a CSR with 'generate-csr <common-name>'")
        }
    }
}

// MARK: - generate-csr

extension NailedCommand {

    struct GenerateCSR: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "generate-csr",
            abstract: "Generate a Certificate Signing Request for the Secure Enclave identity"
        )

        @Argument(help: "The Common Name (CN) for the CSR subject.")
        var commonName: String

        @Option(name: [.short, .customLong("output")], help: "Write PEM to FILE instead of stdout.")
        var output: String?

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: generate-csr", category: "cli")

            guard try core.hasIdentity() else {
                throw ValidationError("no identity found. Run 'generate-identity' first.")
            }

            let csrDER = try core.generateCSR(commonName: commonName)
            let pem = NailedCore.derToPEM(csrDER, label: "CERTIFICATE REQUEST")

            if let path = output {
                try pem.write(toFile: path, atomically: true, encoding: .utf8)
                printStderr("CSR written to \(path)")
            } else {
                print(pem, terminator: "")
            }
        }
    }
}

// MARK: - import-certificate

extension NailedCommand {

    struct ImportCertificate: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "import-certificate",
            abstract: "Import a signed certificate (PEM or DER) for the Secure Enclave identity"
        )

        @Argument(help: "Path to the certificate file (.pem, .crt, .der).")
        var file: String

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: import-certificate", category: "cli")

            guard try core.hasIdentity() else {
                throw ValidationError("no identity found. Run 'generate-identity' first.")
            }

            let fileData = try Data(contentsOf: URL(fileURLWithPath: file))
            let derData = NailedCore.parseCertificateData(from: fileData)

            do {
                try core.importCertificate(certificateData: derData)
            } catch NailedCoreError.certificateAlreadyExists {
                throw ValidationError("certificate already exists in the keychain")
            }

            print("Certificate imported successfully.")

            if let info = try core.getCertificateInfo() {
                if let cn = info.commonName {
                    print("  Subject CN: \(cn)")
                }
                if let issuer = info.issuerCommonName {
                    print("  Issuer CN:  \(issuer)")
                }
            }
        }
    }
}

// MARK: - export-certificate

extension NailedCommand {

    struct ExportCertificate: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "export-certificate",
            abstract: "Export the certificate for the Secure Enclave identity in PEM format"
        )

        @Option(name: [.short, .customLong("output")], help: "Write PEM to FILE instead of stdout.")
        var output: String?

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: export-certificate", category: "cli")

            guard try core.hasIdentity() else {
                throw ValidationError("no identity found. Run 'generate-identity' first.")
            }

            guard try core.hasCertificate() else {
                throw ValidationError("no certificate imported yet. Run 'import-certificate' first.")
            }

            guard let certDER = try core.exportCertificate() else {
                throw ValidationError("failed to export certificate data")
            }

            let pem = NailedCore.derToPEM(certDER, label: "CERTIFICATE")

            if let path = output {
                try pem.write(toFile: path, atomically: true, encoding: .utf8)
                printStderr("Certificate written to \(path)")
            } else {
                print(pem, terminator: "")
            }
        }
    }
}

// MARK: - delete-identity

extension NailedCommand {

    struct DeleteIdentity: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "delete-identity",
            abstract: "Delete the Secure Enclave identity (key pair and certificate). This action cannot be undone."
        )

        @Flag(name: [.short, .long], help: "Skip confirmation prompt.")
        var force = false

        func run() throws {
            let log = NailedLogger.shared
            let core = try initCore()

            log.info("CLI command: delete-identity", category: "cli")

            guard try core.hasIdentity() else {
                printStderr("No identity to delete.")
                return
            }

            if !force {
                printStderr("This will permanently delete the Secure Enclave identity (key + certificate).")
                printStderr("Type 'yes' to confirm: ", terminator: "")
                guard let response = readLine(), response.lowercased() == "yes" else {
                    printStderr("Aborted.")
                    throw ExitCode(1)
                }
            }

            try core.deleteIdentity()
            print("Identity deleted.")
        }
    }
}

// MARK: - enable-login-item

extension NailedCommand {

    struct EnableLoginItem: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "enable-login-item",
            abstract: "Register nailed to launch at login"
        )

        func run() throws {
            NailedLogger.shared.info("CLI command: enable-login-item", category: "cli")
            try SMAppService.mainApp.register()
            print("Login item enabled. nailed will launch at login.")
        }
    }
}

// MARK: - disable-login-item

extension NailedCommand {

    struct DisableLoginItem: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "disable-login-item",
            abstract: "Remove nailed from login items"
        )

        func run() throws {
            NailedLogger.shared.info("CLI command: disable-login-item", category: "cli")
            try SMAppService.mainApp.unregister()
            print("Login item disabled.")
        }
    }
}
