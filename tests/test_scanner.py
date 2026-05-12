from __future__ import annotations

import importlib.util
import io
import plistlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan_apple_app_review_risks.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("scan_apple_app_review_risks", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scanner = load_scanner()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_plist(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump(content, handle)


def write_project(root: Path, settings: str) -> None:
    write_text(root / "Fixture.xcodeproj" / "project.pbxproj", settings)


class ScannerTests(unittest.TestCase):
    def test_parse_xcodebuild_list_and_build_settings_json(self):
        schemes, targets = scanner.parse_xcodebuild_list_json(
            '{"project":{"schemes":["Fixture"],"targets":["Fixture","Widget"]}}'
        )
        self.assertEqual(schemes, ["Fixture"])
        self.assertEqual(targets, ["Fixture", "Widget"])

        parsed = scanner.parse_show_build_settings_json(
            """
            [
              {
                "target": "Fixture",
                "buildSettings": {
                  "PRODUCT_BUNDLE_IDENTIFIER": "com.example.fixture",
                  "PRODUCT_TYPE": "com.apple.product-type.application",
                  "SDKROOT": "iphoneos",
                  "SUPPORTED_PLATFORMS": "iphoneos iphonesimulator",
                  "TARGETED_DEVICE_FAMILY": "1,2"
                }
              }
            ]
            """
        )
        self.assertEqual(parsed[0].name, "Fixture")
        self.assertEqual(parsed[0].bundle_identifier, "com.example.fixture")
        self.assertEqual(parsed[0].platforms, ["iOS", "iPadOS"])

    def test_detects_ios_ipados_fixture_and_missing_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(
                root,
                """
                PRODUCT_BUNDLE_IDENTIFIER = com.example.fixture;
                PRODUCT_TYPE = com.apple.product-type.application;
                SDKROOT = iphoneos;
                SUPPORTED_PLATFORMS = "iphoneos iphonesimulator";
                TARGETED_DEVICE_FAMILY = "1,2";
                """,
            )
            write_plist(
                root / "Info.plist",
                {"CFBundleName": "Fixture", "CFBundleIdentifier": "com.example.fixture", "UIDeviceFamily": [1, 2]},
            )
            write_text(
                root / "Sources" / "View.swift",
                """
                import AppTrackingTransparency
                import CoreLocation

                func request() {
                    CLLocationManager().requestWhenInUseAuthorization()
                    ATTrackingManager.requestTrackingAuthorization { _ in }
                }
                """,
            )

            result = scanner.scan_result(root)
            platforms = {target.platform for target in result.target_platforms}
            finding_ids = {finding.id for finding in result.findings}

            self.assertTrue({"iOS", "iPadOS"} <= platforms)
            self.assertIn("permissions-missing-nslocationwheninuseusagedescription", finding_ids)
            self.assertIn("tracking-missing-nsusertrackingusagedescription", finding_ids)
            self.assertIn("privacy-no-privacy-manifest", finding_ids)
            self.assertTrue(any(check.name == "App Store metadata and screenshots" for check in result.artifact_checks))

    def test_detects_macos_sandbox_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(
                root,
                """
                PRODUCT_BUNDLE_IDENTIFIER = com.example.mac;
                PRODUCT_TYPE = com.apple.product-type.application;
                SDKROOT = macosx;
                SUPPORTED_PLATFORMS = "macosx";
                ENABLE_HARDENED_RUNTIME = YES;
                """,
            )
            write_plist(root / "Mac.entitlements", {"com.apple.security.app-sandbox": True})
            write_text(root / "Sources" / "App.swift", "import AppKit\nNSApplication.shared.run()\n")

            result = scanner.scan_result(root)
            platforms = {target.platform for target in result.target_platforms}

            self.assertIn("macOS", platforms)
            self.assertEqual(result.targets[0].submission_path, "macOS App Store or notarization")

    def test_detects_watchos_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(
                root,
                """
                PRODUCT_BUNDLE_IDENTIFIER = com.example.watchkitapp;
                PRODUCT_TYPE = com.apple.product-type.application.watchapp2;
                SDKROOT = watchos;
                SUPPORTED_PLATFORMS = "watchos watchsimulator";
                """,
            )
            write_plist(root / "WatchInfo.plist", {"CFBundleName": "Watch", "WKWatchKitApp": True})
            write_text(root / "Sources" / "WatchApp.swift", "import WatchKit\nWKApplication.shared()\n")

            result = scanner.scan_result(root)
            platforms = {target.platform for target in result.target_platforms}

            self.assertIn("watchOS", platforms)

    def test_flags_storekit_external_purchase_and_artifact_need(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "Info.plist", {"CFBundleName": "Store", "UIDeviceFamily": [1]})
            write_text(
                root / "Sources" / "Paywall.swift",
                """
                import StoreKit
                let copy = "Subscribe on the web to continue"
                """,
            )

            result = scanner.scan_result(root)
            finding_ids = {finding.id for finding in result.findings}
            artifact_names = {check.name for check in result.artifact_checks}

            self.assertIn("storekit-external-purchase-language", finding_ids)
            self.assertIn("storekit-missing-restore-path", finding_ids)
            self.assertIn("In-app purchase/subscription product configuration", artifact_names)

    def test_privacy_manifest_required_reason_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "PrivacyInfo.xcprivacy", {"NSPrivacyAccessedAPITypes": []})
            write_text(root / "Sources" / "Prefs.swift", "let enabled = UserDefaults.standard.bool(forKey: \"enabled\")\n")

            result = scanner.scan_result(root)
            finding_ids = {finding.id for finding in result.findings}

            self.assertIn("privacy-missing-required-reason-user-defaults", finding_ids)

    def test_suppression_file_suppresses_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "Info.plist", {"CFBundleName": "Store", "UIDeviceFamily": [1]})
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Subscribe on the web"\n')
            write_text(
                root / ".appstore-review-risk.yml",
                """
                suppressions:
                  - id: storekit-external-purchase-language
                    reason: "Internal admin copy, not shipped in submitted app target."
                """,
            )

            result = scanner.scan_result(root)
            finding_ids = {finding.id for finding in result.findings}

            self.assertNotIn("storekit-external-purchase-language", finding_ids)
            self.assertEqual(result.suppressions_applied[0].finding_id, "storekit-external-purchase-language")

    def test_compact_output_limits_detail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "Info.plist", {"CFBundleName": "Store", "UIDeviceFamily": [1]})
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Subscribe on the web"\n')

            result = scanner.scan_result(root)
            output = io.StringIO()
            with redirect_stdout(output):
                scanner.print_compact(root, result, max_findings=1)
            rendered = output.getvalue()

            self.assertIn("Apple App Review Risk Scan Summary", rendered)
            self.assertIn("storekit-external-purchase-language", rendered)
            self.assertIn("more finding", rendered)
            self.assertNotIn("Confirm the app is not steering", rendered)


if __name__ == "__main__":
    unittest.main()
