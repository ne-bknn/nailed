// SPDX-License-Identifier: Apache-2.0

import Foundation

enum RuntimeMode {
    case cli(command: String, arguments: [String])
    case daemon
    case app
}

extension RuntimeMode {
    static func resolve(from args: [String]) -> RuntimeMode {
        guard let first = args.first else { return .app }
        if first == "daemon" { return .daemon }
        if NailedCLI.isCommand(first) { return .cli(command: first, arguments: args) }
        return .app
    }
}
