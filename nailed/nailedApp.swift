// SPDX-License-Identifier: Apache-2.0
//
//  NailedApp.swift
//  nailed
//
//  Created by Timofey Mischenko on 24.06.2025.
//

import SwiftUI

struct NailedApp: App {
    @NSApplicationDelegateAdaptor(NailedAppDelegate.self) var delegate

    var body: some Scene {
        MenuBarExtra("nailed", systemImage: "lock.shield") {
            MenuBarView()
                .environmentObject(delegate.appService)
        }
    }
}
