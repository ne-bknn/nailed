// SPDX-License-Identifier: Apache-2.0

import Foundation
import AppKit

let args = CommandLine.arguments.dropFirst()

if let first = args.first, NailedCommand.isCliInvocation(first) {
    NSApplication.shared.setActivationPolicy(.prohibited)
    NailedCommand.main()
} else {
    NSApplication.shared.setActivationPolicy(.accessory)
    NailedApp.main()
}
