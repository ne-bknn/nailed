// SPDX-License-Identifier: Apache-2.0

import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var appService: AppService

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(
                appService.serverStatus.isRunning ? "Server running" : "Server stopped",
                systemImage: appService.serverStatus.isRunning ? "checkmark.circle" : "xmark.circle"
            )

            Divider()

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding(8)
    }
}
