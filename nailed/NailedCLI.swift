// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Command-line interface for nailed — manage Secure Enclave identities without the GUI.
enum NailedCLI {
    
    private static let log = NailedLogger.shared
    
    private static let commands: Set<String> = [
        "status", "generate-identity", "generate-csr",
        "import-certificate", "export-certificate", "delete-identity"
    ]
    
    /// Returns true if the argument looks like a CLI command (not a GUI launch).
    static func isCommand(_ arg: String) -> Bool {
        commands.contains(arg) || ["help", "--help", "-h", "version", "--version"].contains(arg)
    }
    
    /// Main entry point — parse arguments, run the command, then exit.
    static func run(arguments: [String]) -> Never {
        guard let command = arguments.first else {
            printUsage()
            exit(1)
        }
        
        log.info("CLI command: \(command)", category: "cli")
        let subArgs = Array(arguments.dropFirst())
        
        switch command {
        case "help", "--help", "-h":
            printUsage()
        case "version", "--version":
            print("nailed 1.0.0")
        case "status":
            runStatus()
        case "generate-identity":
            runGenerateIdentity()
        case "generate-csr":
            runGenerateCSR(arguments: subArgs)
        case "import-certificate":
            runImportCertificate(arguments: subArgs)
        case "export-certificate":
            runExportCertificate(arguments: subArgs)
        case "delete-identity":
            runDeleteIdentity(arguments: subArgs)
        default:
            printError("unknown command: \(command)")
            printUsage()
            exit(1)
        }
        
        exit(0)
    }
    
    // MARK: - Commands
    
    private static func runStatus() {
        let core = initCore()
        
        do {
            guard try core.hasIdentity() else {
                print("Identity: not found")
                print("  No Secure Enclave key pair exists. Run 'generate-identity' to create one.")
                exit(0)
            }
            
            print("Identity: present")
            print("  Private key available in Secure Enclave")
            
            guard try core.hasCertificate() else {
                print("  Certificate: not imported")
                print("  Generate a CSR with 'generate-csr' and import the signed certificate with 'import-certificate'.")
                exit(0)
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
            
            exit(0)
        } catch {
            log.error("Failed to query identity status: \(error.localizedDescription)", category: "cli")
            die("failed to query identity status: \(error.localizedDescription)")
        }
    }
    
    private static func runGenerateIdentity() {
        let core = initCore()
        
        do {
            if try core.hasIdentity() {
                printStderr("warning: existing identity will be replaced")
            }
            
            try core.generateIdentity()
            print("Identity generated successfully.")
            print("  A new EC P-256 key pair has been created in the Secure Enclave.")
            print("  Next step: generate a CSR with 'generate-csr <common-name>'")
            exit(0)
        } catch {
            log.error("Failed to generate identity: \(error.localizedDescription)", category: "cli")
            die("failed to generate identity: \(error.localizedDescription)")
        }
    }
    
    private static func runGenerateCSR(arguments: [String]) {
        var commonName: String?
        var outputPath: String?
        
        var i = 0
        while i < arguments.count {
            switch arguments[i] {
            case "-o", "--output":
                guard i + 1 < arguments.count else {
                    die("--output requires a file path argument")
                }
                outputPath = arguments[i + 1]
                i += 2
            case "--help", "-h":
                print("Usage: nailed generate-csr <common-name> [-o FILE]")
                print("")
                print("Generate a Certificate Signing Request for the Secure Enclave identity.")
                print("")
                print("Arguments:")
                print("  <common-name>    The Common Name (CN) for the CSR subject")
                print("")
                print("Options:")
                print("  -o, --output FILE   Write PEM to FILE instead of stdout")
                exit(0)
            default:
                if arguments[i].hasPrefix("-") {
                    die("unknown option: \(arguments[i]). See 'nailed generate-csr --help'")
                }
                if commonName == nil {
                    commonName = arguments[i]
                } else {
                    die("unexpected argument: \(arguments[i]). Common name must be a single quoted string if it contains spaces.")
                }
                i += 1
            }
        }
        
        guard let cn = commonName else {
            die("missing required argument: <common-name>. See 'nailed generate-csr --help'")
        }
        
        let core = initCore()
        
        do {
            guard try core.hasIdentity() else {
                die("no identity found. Run 'generate-identity' first.")
            }
            
            let csrDER = try core.generateCSR(commonName: cn)
            let pem = NailedCore.derToPEM(csrDER, label: "CERTIFICATE REQUEST")
            
            if let path = outputPath {
                try pem.write(toFile: path, atomically: true, encoding: .utf8)
                printStderr("CSR written to \(path)")
            } else {
                print(pem, terminator: "")
            }
            
            exit(0)
        } catch {
            log.error("Failed to generate CSR: \(error.localizedDescription)", category: "cli")
            die("failed to generate CSR: \(error.localizedDescription)")
        }
    }
    
    private static func runImportCertificate(arguments: [String]) {
        var filePath: String?
        
        for arg in arguments {
            if arg == "--help" || arg == "-h" {
                print("Usage: nailed import-certificate <FILE>")
                print("")
                print("Import a signed certificate (PEM or DER) for the Secure Enclave identity.")
                print("")
                print("Arguments:")
                print("  <FILE>    Path to the certificate file (.pem, .crt, .der)")
                exit(0)
            }
            if arg.hasPrefix("-") {
                die("unknown option: \(arg). See 'nailed import-certificate --help'")
            }
            if filePath == nil {
                filePath = arg
            } else {
                die("unexpected argument: \(arg)")
            }
        }
        
        guard let path = filePath else {
            die("missing required argument: <FILE>. See 'nailed import-certificate --help'")
        }
        
        let core = initCore()
        
        do {
            guard try core.hasIdentity() else {
                die("no identity found. Run 'generate-identity' first.")
            }
            
            let fileData = try Data(contentsOf: URL(fileURLWithPath: path))
            let derData = NailedCore.parseCertificateData(from: fileData)
            try core.importCertificate(certificateData: derData)
            
            print("Certificate imported successfully.")
            
            if let info = try core.getCertificateInfo() {
                if let cn = info.commonName {
                    print("  Subject CN: \(cn)")
                }
                if let issuer = info.issuerCommonName {
                    print("  Issuer CN:  \(issuer)")
                }
            }
            
            exit(0)
        } catch let error as NailedCoreError {
            log.error("Certificate import error: \(error.localizedDescription)", category: "cli")
            switch error {
            case .certificateAlreadyExists:
                die("certificate already exists in the keychain")
            default:
                die(error.localizedDescription)
            }
        } catch {
            log.error("Failed to import certificate: \(error.localizedDescription)", category: "cli")
            die("failed to import certificate: \(error.localizedDescription)")
        }
    }
    
    private static func runExportCertificate(arguments: [String]) {
        var outputPath: String?
        
        var i = 0
        while i < arguments.count {
            switch arguments[i] {
            case "-o", "--output":
                guard i + 1 < arguments.count else {
                    die("--output requires a file path argument")
                }
                outputPath = arguments[i + 1]
                i += 2
            case "--help", "-h":
                print("Usage: nailed export-certificate [-o FILE]")
                print("")
                print("Export the certificate for the Secure Enclave identity in PEM format.")
                print("")
                print("Options:")
                print("  -o, --output FILE   Write PEM to FILE instead of stdout")
                exit(0)
            default:
                die("unexpected argument: \(arguments[i]). See 'nailed export-certificate --help'")
            }
        }
        
        let core = initCore()
        
        do {
            guard try core.hasIdentity() else {
                die("no identity found. Run 'generate-identity' first.")
            }
            
            guard try core.hasCertificate() else {
                die("no certificate imported yet. Run 'import-certificate' first.")
            }
            
            guard let certDER = try core.exportCertificate() else {
                die("failed to export certificate data")
            }
            
            let pem = NailedCore.derToPEM(certDER, label: "CERTIFICATE")
            
            if let path = outputPath {
                try pem.write(toFile: path, atomically: true, encoding: .utf8)
                printStderr("Certificate written to \(path)")
            } else {
                print(pem, terminator: "")
            }
            
            exit(0)
        } catch {
            log.error("Failed to export certificate: \(error.localizedDescription)", category: "cli")
            die("failed to export certificate: \(error.localizedDescription)")
        }
    }
    
    private static func runDeleteIdentity(arguments: [String]) {
        var force = false
        
        for arg in arguments {
            switch arg {
            case "--force", "-f":
                force = true
            case "--help", "-h":
                print("Usage: nailed delete-identity [--force]")
                print("")
                print("Delete the Secure Enclave identity (key pair and certificate).")
                print("This action cannot be undone.")
                print("")
                print("Options:")
                print("  -f, --force   Skip confirmation prompt")
                exit(0)
            default:
                die("unexpected argument: \(arg). See 'nailed delete-identity --help'")
            }
        }
        
        let core = initCore()
        
        do {
            guard try core.hasIdentity() else {
                printStderr("No identity to delete.")
                exit(0)
            }
            
            if !force {
                printStderr("This will permanently delete the Secure Enclave identity (key + certificate).")
                printStderr("Type 'yes' to confirm: ", terminator: "")
                guard let response = readLine(), response.lowercased() == "yes" else {
                    printStderr("Aborted.")
                    exit(1)
                }
            }
            
            try core.deleteIdentity()
            print("Identity deleted.")
            exit(0)
        } catch {
            log.error("Failed to delete identity: \(error.localizedDescription)", category: "cli")
            die("failed to delete identity: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Helpers
    
    private static func initCore() -> NailedCore {
        do {
            return try NailedCore()
        } catch {
            die("failed to initialize: \(error.localizedDescription)")
        }
    }
    
    private static func printUsage() {
        let usage = """
        nailed — Secure Enclave identity manager
        
        Usage: nailed <command> [options]
        
        Commands:
          status                          Show identity and certificate status
          generate-identity               Generate a new Secure Enclave key pair
          generate-csr <CN> [-o FILE]     Generate a Certificate Signing Request
          import-certificate <FILE>       Import a signed certificate (PEM or DER)
          export-certificate [-o FILE]    Export the certificate in PEM format
          delete-identity [--force]       Delete the identity (irreversible)
        
        Run 'nailed <command> --help' for details on a specific command.
        
        When invoked without a command, the GUI application launches.
        """
        print(usage)
    }
    
    private static func printError(_ message: String) {
        printStderr("error: \(message)")
    }
    
    private static func printStderr(_ message: String, terminator: String = "\n") {
        FileHandle.standardError.write(Data((message + terminator).utf8))
    }
    
    private static func die(_ message: String) -> Never {
        printError(message)
        exit(1)
    }
}
