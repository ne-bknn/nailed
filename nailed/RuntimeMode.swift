// SPDX-License-Identifier: Apache-2.0

import Foundation

enum RuntimeMode {
    case cli(command: String, arguments: [String])
    case app
}

extension RuntimeMode {
    static func resolve(from args: [String]) -> RuntimeMode {
        guard let first = args.first else { return .app }
        if NailedCLI.isCommand(first) { return .cli(command: first, arguments: args) }
        return .app
    }
}
