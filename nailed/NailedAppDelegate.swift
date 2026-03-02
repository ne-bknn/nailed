// SPDX-License-Identifier: Apache-2.0

import AppKit

final class NailedAppDelegate: NSObject, NSApplicationDelegate {
    let appService = AppService()

    func applicationDidFinishLaunching(_ notification: Notification) {
        appService.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        appService.stopServer()
    }
}
