// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Centralized, file-based logger for nailed.
///
/// Writes structured log lines to `~/Library/Logs/nailed/nailed.log`
/// and mirrors every entry to stderr so Xcode / terminal output still works.
final class NailedLogger {

    // MARK: - Public types

    enum Level: String {
        case debug   = "DEBUG"
        case info    = "INFO"
        case warning = "WARNING"
        case error   = "ERROR"
    }

    // MARK: - Singleton

    static let shared = NailedLogger()

    // MARK: - Properties

    /// URL of the current log file.  Exposed so the UI can share it.
    let logFileURL: URL

    private let queue = DispatchQueue(label: "com.nailed.logger", qos: .utility)
    private let fileHandle: FileHandle?
    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    // MARK: - Init

    private init() {
        let logsDir: URL
        if let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first {
            logsDir = library.appendingPathComponent("Logs/nailed", isDirectory: true)
        } else {
            logsDir = FileManager.default.temporaryDirectory.appendingPathComponent("nailed-logs", isDirectory: true)
        }

        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)

        let fileURL = logsDir.appendingPathComponent("nailed.log")
        self.logFileURL = fileURL

        // Create the file if it doesn't exist, then open for appending.
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        }

        self.fileHandle = try? FileHandle(forWritingTo: fileURL)
        self.fileHandle?.seekToEndOfFile()
    }

    deinit {
        try? fileHandle?.close()
    }

    // MARK: - Convenience methods

    func debug(_ message: String, category: String) {
        log(level: .debug, category: category, message: message)
    }

    func info(_ message: String, category: String) {
        log(level: .info, category: category, message: message)
    }

    func warning(_ message: String, category: String) {
        log(level: .warning, category: category, message: message)
    }

    func error(_ message: String, category: String) {
        log(level: .error, category: category, message: message)
    }

    // MARK: - Core

    private func log(level: Level, category: String, message: String) {
        let timestamp = dateFormatter.string(from: Date())
        let line = "[\(timestamp)] [\(level.rawValue)] [\(category)] \(message)\n"

        queue.async { [weak self] in
            // Write to log file
            if let data = line.data(using: .utf8) {
                self?.fileHandle?.write(data)
            }

            // Mirror to stderr so Xcode console / CLI still shows output
            FileHandle.standardError.write(line.data(using: .utf8) ?? Data())
        }
    }
}
