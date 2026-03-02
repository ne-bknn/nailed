// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import AppKit

struct MenuBarView: View {
    @EnvironmentObject var appService: AppService

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Group {
                serverStatusItem
                identityStatusItem
                Text("nailed \(AppVersion.version)")
            }
            .font(.callout)
            .foregroundColor(.secondary)
            Divider()
            showLogButton
            Divider()
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding(8)
    }

    // MARK: - Server status

    private var serverStatusItem: some View {
        Label(
            appService.serverStatus.isRunning ? "Server running" : "Server stopped",
            systemImage: appService.serverStatus.isRunning ? "checkmark.circle" : "xmark.circle"
        )
    }

    // MARK: - Identity status

    private var identityStatusItem: some View {
        Group {
            if appService.hasIdentity {
                if appService.hasCertificate, let cn = appService.certificateInfo?.commonName {
                    Label("Identity: \(cn)", systemImage: "key.fill")
                } else if appService.hasCertificate {
                    Label("Identity: certificate imported", systemImage: "key.fill")
                } else {
                    Label("Identity: no certificate", systemImage: "key")
                        .foregroundColor(.secondary)
                }
            } else {
                Label("Identity: not configured", systemImage: "key.slash")
                    .foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Log file

    private var showLogButton: some View {
        Button("Show Log in Finder") {
            let logURL = appService.logFileURL
            NSWorkspace.shared.selectFile(logURL.path, inFileViewerRootedAtPath: logURL.deletingLastPathComponent().path)
        }
        .disabled(!FileManager.default.fileExists(atPath: appService.logFileURL.path))
    }
}
