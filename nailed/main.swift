// SPDX-License-Identifier: Apache-2.0

import Foundation
import AppKit

// If the first argument after the executable name is a known CLI command,
// run in headless CLI mode.  Otherwise launch the normal SwiftUI GUI.
let args = Array(CommandLine.arguments.dropFirst())

if let firstArg = args.first, NailedCLI.isCommand(firstArg) {
    // Prevent dock icon / window-server connection when running as a CLI tool.
    NSApplication.shared.setActivationPolicy(.prohibited)
    NailedCLI.run(arguments: args)
} else {
    NailedApp.main()
}
