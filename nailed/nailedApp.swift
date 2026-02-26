// SPDX-License-Identifier: Apache-2.0
//
//  NailedApp.swift
//  nailed
//
//  Created by Timofey Mischenko on 24.06.2025.
//

import SwiftUI

struct NailedApp: App {
    @StateObject private var appService = AppService()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appService)
                .task { appService.start() }
        }
    }
}
