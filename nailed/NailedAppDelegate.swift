// SPDX-License-Identifier: Apache-2.0

import AppKit

final class NailedAppDelegate: NSObject, NSApplicationDelegate {
    let appService = AppService()

    func applicationDidFinishLaunching(_ notification: Notification) {
        appService.start()
        // MenuBarExtra presence prevents SwiftUI from auto-activating the app;
        // activate explicitly so the WindowGroup window appears on launch.
        NSApp.activate(ignoringOtherApps: true)
    }
}
