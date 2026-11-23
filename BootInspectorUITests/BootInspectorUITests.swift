//
//  BootInspectorUITests.swift
//  BootInspectorUITests
//
//  Created by Tim Sanvido on 11/20/26.
//

import XCTest

final class BootInspectorUITests: XCTestCase {

    @MainActor
    func testLaunchAndSwitchInspectionModes() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["Open Image..."].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["HFS / ISO Partition & Blessing Inspector"].exists)

        let playStation = app.radioButtons["PlayStation"]
        (playStation.exists ? playStation : app.buttons["PlayStation"]).click()
        XCTAssertTrue(app.staticTexts["PlayStation Disc Inspector"].exists)
        XCTAssertTrue(app.buttons["Scan Library…"].exists)

        let macOS = app.radioButtons["Mac OS"]
        (macOS.exists ? macOS : app.buttons["Mac OS"]).click()
        XCTAssertTrue(app.staticTexts["HFS / ISO Partition & Blessing Inspector"].exists)
    }

    @MainActor
    func testLaunchPerformance() throws {
        // This measures how long it takes to launch your application.
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}
