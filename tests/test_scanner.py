from __future__ import annotations

import importlib.util
import io
import plistlib
import subprocess
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


def write_xml_project(root: Path, objects: dict) -> None:
    path = root / "Fixture.xcodeproj" / "project.pbxproj"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump({"objects": objects}, handle)


def run_git(root: Path, args: list[str]) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def commit_all(root: Path, message: str) -> None:
    run_git(root, ["add", "."])
    run_git(root, ["-c", "user.name=Test User", "-c", "user.email=test@example.com", "commit", "-m", message])


def fixture_pbxproj() -> str:
    return """
// !$*UTF8*$!
{
  objects = {
    AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */ = {isa = PBXFileReference; path = App/AppView.swift; sourceTree = "<group>"; };
    BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */ = {isa = PBXFileReference; path = Admin/AdminView.swift; sourceTree = "<group>"; };
    CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */ = {isa = PBXBuildFile; fileRef = AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */; };
    DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */ = {isa = PBXBuildFile; fileRef = BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */; };
    EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */ = {isa = PBXSourcesBuildPhase; files = (CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */, ); };
    FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */ = {isa = PBXSourcesBuildPhase; files = (DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */, ); };
    111111111111111111111111 /* SubmittedApp */ = {isa = PBXNativeTarget; buildPhases = (EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */, ); name = SubmittedApp; productType = "com.apple.product-type.application"; };
    222222222222222222222222 /* AdminApp */ = {isa = PBXNativeTarget; buildPhases = (FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */, ); name = AdminApp; productType = "com.apple.product-type.application"; };
  };
}
"""


def fixture_pbxproj_with_build_configs() -> str:
    return """
// !$*UTF8*$!
{
  objects = {
    AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */ = {isa = PBXFileReference; path = App/AppView.swift; sourceTree = "<group>"; };
    BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */ = {isa = PBXFileReference; path = Admin/AdminView.swift; sourceTree = "<group>"; };
    CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */ = {isa = PBXBuildFile; fileRef = AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */; };
    DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */ = {isa = PBXBuildFile; fileRef = BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */; };
    EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */ = {isa = PBXSourcesBuildPhase; files = (CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */, ); };
    FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */ = {isa = PBXSourcesBuildPhase; files = (DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */, ); };
    A11111111111111111111111 /* App Debug */ = {isa = XCBuildConfiguration; buildSettings = { INFOPLIST_FILE = App/Info.plist; PRODUCT_BUNDLE_IDENTIFIER = com.example.app; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1; }; name = Debug; };
    A22222222222222222222222 /* App Config List */ = {isa = XCConfigurationList; buildConfigurations = (A11111111111111111111111 /* App Debug */, ); };
    B11111111111111111111111 /* Admin Debug */ = {isa = XCBuildConfiguration; buildSettings = { INFOPLIST_FILE = Admin/Info.plist; PRODUCT_BUNDLE_IDENTIFIER = com.example.admin; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = macosx; }; name = Debug; };
    B22222222222222222222222 /* Admin Config List */ = {isa = XCConfigurationList; buildConfigurations = (B11111111111111111111111 /* Admin Debug */, ); };
    111111111111111111111111 /* SubmittedApp */ = {isa = PBXNativeTarget; buildConfigurationList = A22222222222222222222222 /* App Config List */; buildPhases = (EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */, ); name = SubmittedApp; productType = "com.apple.product-type.application"; };
    222222222222222222222222 /* AdminApp */ = {isa = PBXNativeTarget; buildConfigurationList = B22222222222222222222222 /* Admin Config List */; buildPhases = (FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */, ); name = AdminApp; productType = "com.apple.product-type.application"; };
  };
}
"""


def fixture_xml_pbx_objects() -> dict:
    return {
        "FILE_APP": {"isa": "PBXFileReference", "path": "App/AppView.swift"},
        "FILE_TEST": {"isa": "PBXFileReference", "path": "Tests/AppTests.swift"},
        "BUILD_APP": {"isa": "PBXBuildFile", "fileRef": "FILE_APP"},
        "BUILD_TEST": {"isa": "PBXBuildFile", "fileRef": "FILE_TEST"},
        "PHASE_APP": {"isa": "PBXSourcesBuildPhase", "files": ["BUILD_APP"]},
        "PHASE_TEST": {"isa": "PBXSourcesBuildPhase", "files": ["BUILD_TEST"]},
        "CONFIG_APP": {
            "isa": "XCBuildConfiguration",
            "buildSettings": {
                "PRODUCT_BUNDLE_IDENTIFIER": "com.example.xml",
                "PRODUCT_TYPE": "com.apple.product-type.application",
                "SDKROOT": "iphoneos",
                "TARGETED_DEVICE_FAMILY": "1",
            },
        },
        "CONFIG_TEST": {
            "isa": "XCBuildConfiguration",
            "buildSettings": {
                "PRODUCT_BUNDLE_IDENTIFIER": "com.example.xmlTests",
                "PRODUCT_TYPE": "com.apple.product-type.bundle.unit-test",
                "SDKROOT": "iphoneos",
                "TARGETED_DEVICE_FAMILY": "1",
            },
        },
        "CONFIG_LIST_APP": {"isa": "XCConfigurationList", "buildConfigurations": ["CONFIG_APP"]},
        "CONFIG_LIST_TEST": {"isa": "XCConfigurationList", "buildConfigurations": ["CONFIG_TEST"]},
        "TARGET_APP": {
            "isa": "PBXNativeTarget",
            "name": "XmlApp",
            "productType": "com.apple.product-type.application",
            "buildPhases": ["PHASE_APP"],
            "buildConfigurationList": "CONFIG_LIST_APP",
        },
        "TARGET_TEST": {
            "isa": "PBXNativeTarget",
            "name": "XmlAppTests",
            "productType": "com.apple.product-type.bundle.unit-test",
            "buildPhases": ["PHASE_TEST"],
            "buildConfigurationList": "CONFIG_LIST_TEST",
        },
    }


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

        test_target = scanner.target_from_settings(
            "FixtureTests",
            {
                "PRODUCT_TYPE": "com.apple.product-type.bundle.unit-test",
                "SDKROOT": "iphoneos",
                "TARGETED_DEVICE_FAMILY": "1",
            },
            ["test target"],
        )
        self.assertEqual(test_target.submission_path, "Not submitted app target")

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

    def test_skips_placeholder_info_plist_target_when_project_target_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(
                root,
                """
                PRODUCT_BUNDLE_IDENTIFIER = com.example.fixture;
                PRODUCT_NAME = Fixture;
                SDKROOT = iphoneos;
                TARGETED_DEVICE_FAMILY = 1;
                """,
            )
            write_plist(
                root / "Info.plist",
                {
                    "CFBundleName": "$(PRODUCT_NAME)",
                    "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
                    "CFBundlePackageType": "APPL",
                    "UIDeviceFamily": [1],
                },
            )

            result = scanner.scan_result(root)
            target_names = [target.name for target in result.targets]

            self.assertIn("Fixture", target_names)
            self.assertNotIn("$(PRODUCT_NAME)", target_names)

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

    def test_diff_mode_reports_new_working_tree_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "Info.plist", {"CFBundleName": "Store", "UIDeviceFamily": [1]})
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Welcome"\n')
            commit_all(root, "base")
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Subscribe on the web"\n')

            result = scanner.diff_scan_result(root, base_ref="HEAD")
            new_ids = {finding.id for finding in result.new_findings}
            output = io.StringIO()
            with redirect_stdout(output):
                scanner.print_compact_diff(result, max_findings=4)
            rendered = output.getvalue()

            self.assertIn("Sources/Paywall.swift", result.changed_files)
            self.assertIn("storekit-external-purchase-language", new_ids)
            self.assertEqual(result.head_ref, "working tree")
            self.assertIn("Apple App Review Diff Risk Scan Summary", rendered)
            self.assertIn("storekit-external-purchase-language", rendered)

    def test_diff_mode_reports_resolved_ref_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_plist(root / "Info.plist", {"CFBundleName": "Store", "UIDeviceFamily": [1]})
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Subscribe on the web"\n')
            commit_all(root, "base")
            base_ref = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
            write_text(root / "Sources" / "Paywall.swift", 'let copy = "Welcome"\n')
            commit_all(root, "head")

            result = scanner.diff_scan_result(root, diff_range=f"{base_ref}..HEAD")
            resolved_ids = {finding.id for finding in result.resolved_findings}

            self.assertIn("Sources/Paywall.swift", result.changed_files)
            self.assertIn("storekit-external-purchase-language", resolved_ids)
            self.assertEqual(result.head_ref, "HEAD")

    def test_diff_mode_marks_changed_file_finding_when_display_evidence_is_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            for index in range(9):
                write_text(root / f"OldPaywall{index}.swift", 'let copy = "Subscribe on the web"\n')
            write_text(root / "Sources" / "NewPaywall.swift", 'let copy = "Welcome"\n')
            commit_all(root, "base")
            write_text(root / "Sources" / "NewPaywall.swift", 'let copy = "Subscribe on the web"\n')

            result = scanner.diff_scan_result(root, base_ref="HEAD")
            changed_ids = {finding.id for finding in result.changed_file_findings}
            existing_finding = next(
                finding
                for finding in result.existing_findings
                if finding.id == "storekit-external-purchase-language"
            )

            self.assertIn("Sources/NewPaywall.swift", result.changed_files)
            self.assertFalse(scanner.finding_changed_evidence(existing_finding, ["Sources/NewPaywall.swift"]))
            self.assertIn("storekit-external-purchase-language", changed_ids)

    def test_submitted_target_scopes_code_pattern_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, fixture_pbxproj())
            write_text(root / "App" / "AppView.swift", "import SwiftUI\nlet title = \"Home\"\n")
            write_text(root / "Admin" / "AdminView.swift", 'let copy = "Subscribe on the web"\n')

            unscoped = scanner.scan_result(root)
            scoped = scanner.scan_result(root, submitted_target="SubmittedApp")
            unscoped_ids = {finding.id for finding in unscoped.findings}
            scoped_ids = {finding.id for finding in scoped.findings}

            self.assertIn("storekit-external-purchase-language", unscoped_ids)
            self.assertNotIn("storekit-external-purchase-language", scoped_ids)
            self.assertEqual(scoped.scoped_target, "SubmittedApp")
            self.assertTrue(any(membership.target == "SubmittedApp" for membership in scoped.target_memberships))

    def test_submitted_target_scopes_plist_and_privacy_manifest_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, fixture_pbxproj())
            write_text(
                root / "App" / "AppView.swift",
                "import AVFoundation\nlet camera = AVCaptureDevice.default(for: .video)\n",
            )
            write_text(root / "Admin" / "AdminView.swift", "import SwiftUI\nlet title = \"Admin\"\n")
            write_plist(root / "Admin" / "Info.plist", {"NSCameraUsageDescription": "Capture admin photos."})
            write_plist(root / "Admin" / "PrivacyInfo.xcprivacy", {"NSPrivacyAccessedAPITypes": []})

            unscoped = scanner.scan_result(root)
            scoped = scanner.scan_result(root, submitted_target="SubmittedApp")
            unscoped_ids = {finding.id for finding in unscoped.findings}
            scoped_ids = {finding.id for finding in scoped.findings}

            self.assertNotIn("permissions-missing-nscamerausagedescription", unscoped_ids)
            self.assertNotIn("privacy-no-privacy-manifest", unscoped_ids)
            self.assertIn("permissions-missing-nscamerausagedescription", scoped_ids)
            self.assertIn("privacy-no-privacy-manifest", scoped_ids)

    def test_submitted_target_keeps_adjacent_info_plist_when_build_setting_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, fixture_pbxproj())
            write_text(
                root / "App" / "AppView.swift",
                "import AVFoundation\nlet camera = AVCaptureDevice.default(for: .video)\n",
            )
            write_text(root / "Admin" / "AdminView.swift", "import SwiftUI\nlet title = \"Admin\"\n")
            write_plist(root / "App" / "Info.plist", {"NSCameraUsageDescription": "Capture profile photos."})
            write_plist(root / "Admin" / "Info.plist", {"CFBundleName": "Admin"})

            scoped = scanner.scan_result(root, submitted_target="SubmittedApp")
            scoped_ids = {finding.id for finding in scoped.findings}

            self.assertNotIn("permissions-missing-nscamerausagedescription", scoped_ids)

    def test_static_target_matrix_uses_each_pbx_native_target_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, fixture_pbxproj_with_build_configs())
            write_text(root / "App" / "AppView.swift", "import SwiftUI\n")
            write_text(root / "Admin" / "AdminView.swift", "import AppKit\n")
            write_plist(root / "App" / "Info.plist", {"CFBundleName": "Submitted"})
            write_plist(root / "Admin" / "Info.plist", {"CFBundleName": "Admin"})

            result = scanner.scan_result(root)
            targets = {target.name: target for target in result.targets}

            self.assertEqual(targets["SubmittedApp"].bundle_identifier, "com.example.app")
            self.assertEqual(targets["SubmittedApp"].platforms, ["iOS"])
            self.assertEqual(targets["AdminApp"].bundle_identifier, "com.example.admin")
            self.assertEqual(targets["AdminApp"].platforms, ["macOS"])

    def test_diff_mode_marks_scoped_info_plist_changes_as_changed_file_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_project(root, fixture_pbxproj())
            write_text(
                root / "App" / "AppView.swift",
                "import AVFoundation\nlet camera = AVCaptureDevice.default(for: .video)\n",
            )
            write_plist(root / "App" / "Info.plist", {"CFBundleName": "Fixture"})
            commit_all(root, "base")
            write_plist(root / "App" / "Info.plist", {"CFBundleName": "Fixture", "CFBundleDisplayName": "Fixture"})

            result = scanner.diff_scan_result(root, base_ref="HEAD", submitted_target="SubmittedApp")
            changed_ids = {finding.id for finding in result.changed_file_findings}

            self.assertIn("App/Info.plist", result.changed_files)
            self.assertIn("permissions-missing-nscamerausagedescription", changed_ids)

    def test_xml_pbxproj_auto_scopes_sole_app_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_xml_project(root, fixture_xml_pbx_objects())
            write_text(root / "App" / "AppView.swift", "import SwiftUI\nlet title = \"Home\"\n")
            write_text(root / "Tests" / "AppTests.swift", 'let copy = "Subscribe on the web"\n')

            result = scanner.scan_result(root)
            finding_ids = {finding.id for finding in result.findings}
            target_names = {target.name for target in result.targets}

            self.assertEqual(result.scoped_target, "XmlApp")
            self.assertIn("XmlApp", target_names)
            self.assertNotIn("storekit-external-purchase-language", finding_ids)

    def test_ignores_swiftui_redacted_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_text(root / "Sources" / "LoadingView.swift", "Text(\"Loading\").redacted(reason: .placeholder)\n")

            result = scanner.scan_result(root)
            finding_ids = {finding.id for finding in result.findings}

            self.assertNotIn("app-completeness-placeholder-content", finding_ids)

    def test_repeated_scan_refreshes_changed_source_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            source = root / "Sources" / "Paywall.swift"
            write_text(source, 'let copy = "Welcome"\n')

            initial = scanner.scan_result(root)
            write_text(source, 'let copy = "Subscribe on the web"\n')
            rescanned = scanner.scan_result(root)

            initial_ids = {finding.id for finding in initial.findings}
            rescanned_ids = {finding.id for finding in rescanned.findings}

            self.assertNotIn("storekit-external-purchase-language", initial_ids)
            self.assertIn("storekit-external-purchase-language", rescanned_ids)


if __name__ == "__main__":
    unittest.main()
