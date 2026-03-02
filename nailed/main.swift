// SPDX-License-Identifier: Apache-2.0

import Foundation
import AppKit

let args = Array(CommandLine.arguments.dropFirst())
let mode = RuntimeMode.resolve(from: args)

switch mode {
case .cli(_, _):
    NSApplication.shared.setActivationPolicy(.prohibited)
    NailedCLI.run(arguments: args)

case .app:
    NSApplication.shared.setActivationPolicy(.accessory)
    NailedApp.main()
}
