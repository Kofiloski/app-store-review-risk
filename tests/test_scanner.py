from __future__ import annotations

import importlib.util
import io
import plistlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch


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


def fixture_pbxproj_with_synchronized_groups() -> str:
    return """
// !$*UTF8*$!
{
  objects = {
    CCCCCCCCCCCCCCCCCCCCCCCC /* Exceptions for "App" folder in "SubmittedApp" target */ = {
      isa = PBXFileSystemSynchronizedBuildFileExceptionSet;
      membershipExceptions = (
        Excluded.swift,
      );
      target = 111111111111111111111111 /* SubmittedApp */;
    };
    AAAAAAAAAAAAAAAAAAAAAAAA /* App */ = {
      isa = PBXFileSystemSynchronizedRootGroup;
      exceptions = (
        CCCCCCCCCCCCCCCCCCCCCCCC /* Exceptions for "App" folder in "SubmittedApp" target */,
      );
      explicitFileTypes = {};
      explicitFolders = ();
      path = App;
      sourceTree = "<group>";
    };
    BBBBBBBBBBBBBBBBBBBBBBBB /* Admin */ = {
      isa = PBXFileSystemSynchronizedRootGroup;
      explicitFileTypes = {};
      explicitFolders = ();
      path = Admin;
      sourceTree = "<group>";
    };
    DDDDDDDDDDDDDDDDDDDDDDDD /* Sources */ = {isa = PBXSourcesBuildPhase; files = (); };
    EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */ = {isa = PBXSourcesBuildPhase; files = (); };
    111111111111111111111111 /* SubmittedApp */ = {
      isa = PBXNativeTarget;
      buildPhases = (DDDDDDDDDDDDDDDDDDDDDDDD /* Sources */, );
      fileSystemSynchronizedGroups = (AAAAAAAAAAAAAAAAAAAAAAAA /* App */, );
      name = SubmittedApp;
      productType = "com.apple.product-type.application";
    };
    222222222222222222222222 /* AdminApp */ = {
      isa = PBXNativeTarget;
      buildPhases = (EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */, );
      fileSystemSynchronizedGroups = (BBBBBBBBBBBBBBBBBBBBBBBB /* Admin */, );
      name = AdminApp;
      productType = "com.apple.product-type.application";
    };
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


def fixture_pbxproj_with_generated_info_plist_settings(
    *,
    app_settings: str = "",
    admin_settings: str = "",
    app_release_settings: str | None = None,
    admin_release_settings: str | None = None,
) -> str:
    app_release_settings = app_settings if app_release_settings is None else app_release_settings
    admin_release_settings = admin_settings if admin_release_settings is None else admin_release_settings
    return f"""
// !$*UTF8*$!
{{
  objects = {{
    AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */ = {{isa = PBXFileReference; path = App/AppView.swift; sourceTree = "<group>"; }};
    BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */ = {{isa = PBXFileReference; path = Admin/AdminView.swift; sourceTree = "<group>"; }};
    CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */ = {{isa = PBXBuildFile; fileRef = AAAAAAAAAAAAAAAAAAAAAAAA /* AppView.swift */; }};
    DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */ = {{isa = PBXBuildFile; fileRef = BBBBBBBBBBBBBBBBBBBBBBBB /* AdminView.swift */; }};
    EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */ = {{isa = PBXSourcesBuildPhase; files = (CCCCCCCCCCCCCCCCCCCCCCCC /* AppView.swift in Sources */, ); }};
    FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */ = {{isa = PBXSourcesBuildPhase; files = (DDDDDDDDDDDDDDDDDDDDDDDD /* AdminView.swift in Sources */, ); }};
    A11111111111111111111111 /* App Debug */ = {{isa = XCBuildConfiguration; buildSettings = {{ GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = com.example.app; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1; {app_settings} }}; name = Debug; }};
    A33333333333333333333333 /* App Release */ = {{isa = XCBuildConfiguration; buildSettings = {{ GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = com.example.app; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1; {app_release_settings} }}; name = Release; }};
    A22222222222222222222222 /* App Config List */ = {{isa = XCConfigurationList; buildConfigurations = (A11111111111111111111111 /* App Debug */, A33333333333333333333333 /* App Release */, ); }};
    B11111111111111111111111 /* Admin Debug */ = {{isa = XCBuildConfiguration; buildSettings = {{ GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = com.example.admin; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1; {admin_settings} }}; name = Debug; }};
    B33333333333333333333333 /* Admin Release */ = {{isa = XCBuildConfiguration; buildSettings = {{ GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = com.example.admin; PRODUCT_TYPE = "com.apple.product-type.application"; SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1; {admin_release_settings} }}; name = Release; }};
    B22222222222222222222222 /* Admin Config List */ = {{isa = XCConfigurationList; buildConfigurations = (B11111111111111111111111 /* Admin Debug */, B33333333333333333333333 /* Admin Release */, ); }};
    111111111111111111111111 /* SubmittedApp */ = {{isa = PBXNativeTarget; buildConfigurationList = A22222222222222222222222 /* App Config List */; buildPhases = (EEEEEEEEEEEEEEEEEEEEEEEE /* Sources */, ); name = SubmittedApp; productType = "com.apple.product-type.application"; }};
    222222222222222222222222 /* AdminApp */ = {{isa = PBXNativeTarget; buildConfigurationList = B22222222222222222222222 /* Admin Config List */; buildPhases = (FFFFFFFFFFFFFFFFFFFFFFFF /* Sources */, ); name = AdminApp; productType = "com.apple.product-type.application"; }};
  }};
}}
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


def fixture_xml_pbx_objects_with_synchronized_groups() -> dict:
    return {
        "EXCEPTION_APP": {
            "isa": "PBXFileSystemSynchronizedBuildFileExceptionSet",
            "membershipExceptions": ["Excluded.swift"],
            "target": "TARGET_APP",
        },
        "GROUP_APP": {
            "isa": "PBXFileSystemSynchronizedRootGroup",
            "exceptions": ["EXCEPTION_APP"],
            "explicitFileTypes": {},
            "explicitFolders": [],
            "path": "App",
            "sourceTree": "<group>",
        },
        "GROUP_ADMIN": {
            "isa": "PBXFileSystemSynchronizedRootGroup",
            "explicitFileTypes": {},
            "explicitFolders": [],
            "path": "Admin",
            "sourceTree": "<group>",
        },
        "PHASE_APP": {"isa": "PBXSourcesBuildPhase", "files": []},
        "PHASE_ADMIN": {"isa": "PBXSourcesBuildPhase", "files": []},
        "TARGET_APP": {
            "isa": "PBXNativeTarget",
            "name": "XmlApp",
            "productType": "com.apple.product-type.application",
            "buildPhases": ["PHASE_APP"],
            "fileSystemSynchronizedGroups": ["GROUP_APP"],
        },
        "TARGET_ADMIN": {
            "isa": "PBXNativeTarget",
            "name": "XmlAdmin",
            "productType": "com.apple.product-type.application",
            "buildPhases": ["PHASE_ADMIN"],
            "fileSystemSynchronizedGroups": ["GROUP_ADMIN"],
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

    def test_xcodebuild_show_settings_timeout_falls_back_to_static_discovery(self):
        list_result = subprocess.CompletedProcess(
            args=["xcodebuild"],
            returncode=0,
            stdout='{"project":{"schemes":["Fixture"],"targets":["Fixture"]}}',
            stderr="",
        )
        notes: list[str] = []
        mocked_run = Mock(side_effect=[list_result, subprocess.TimeoutExpired(["xcodebuild"], 60)])
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            scanner.discover_xcodebuild_targets.__globals__,
            {"run_xcodebuild": mocked_run},
        ):
            targets = scanner.discover_xcodebuild_targets(
                Path(tmp),
                project="Fixture.xcodeproj",
                workspace=None,
                scheme=None,
                notes=notes,
            )

        self.assertEqual(targets, [])
        self.assertTrue(any("showBuildSettings failed" in note and "Fixture" in note for note in notes))

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
            self.assertEqual(
                next(finding.severity for finding in result.findings if finding.id == "privacy-no-privacy-manifest"),
                "LOW",
            )
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
            external_purchase = next(
                finding for finding in result.findings if finding.id == "storekit-external-purchase-language"
            )

            self.assertIn("storekit-external-purchase-language", finding_ids)
            self.assertIn("storekit-missing-restore-path", finding_ids)
            self.assertEqual(external_purchase.severity, "MEDIUM")
            self.assertIn("United States storefront", external_purchase.recommendation)
            self.assertIn("In-app purchase/subscription product configuration", artifact_names)

    def test_authentication_and_account_findings_use_current_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "Login.swift",
                "import GoogleSignIn\nlet action = \"Create account\"\n",
            )

            result = scanner.scan_result(root)
            by_id = {finding.id: finding for finding in result.findings}

            login = by_id["authentication-third-party-login-without-apple"]
            deletion = by_id["accounts-missing-account-deletion-flow"]
            self.assertIn("equivalent privacy-preserving option", login.title)
            self.assertIn("Guideline 4.8", login.recommendation)
            self.assertIn("in-app account deletion initiation", deletion.title)

            write_text(
                root / "Login.swift",
                "import LoginWithAmazon\nlet action = \"Create account\"\nfunc deleteAccount() {}\n",
            )
            updated_ids = {finding.id for finding in scanner.scan_result(root).findings}
            self.assertIn("authentication-third-party-login-without-apple", updated_ids)
            self.assertNotIn("accounts-missing-account-deletion-flow", updated_ids)

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

    def test_suppression_requires_a_concrete_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / ".appstore-review-risk.yml",
                "suppressions:\n  - id: storekit-external-purchase-language\n",
            )

            with self.assertRaisesRegex(ValueError, "needs a concrete review-oriented reason"):
                scanner.scan_result(root)

    def test_invalid_json_suppression_returns_clean_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / ".appstore-review-risk.json", "{not json")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = scanner.main([str(root)])

            self.assertEqual(exit_code, 2)
            self.assertIn("Invalid suppression config", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_yaml_suppression_is_rejected(self):
        malformed_documents = (
            "suppressions: invalid\n",
            (
                "suppressions:\n"
                "  - id: storekit-external-purchase-language\n"
                "    unexpected: true\n"
                "    reason: Internal-only copy.\n"
            ),
            (
                "suppressions:\n"
                "  - id: storekit-external-purchase-language\n"
                '    reason: ""\n'
            ),
            (
                "suppressions:\n"
                "  - id: storekit-external-purchase-language\n"
                '    reason: "unterminated\n'
            ),
            (
                "suppressions:\n"
                "  - id: storekit-external-purchase-language\n"
                "    reason: 'Internal' only'\n"
            ),
        )
        for document in malformed_documents:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_text(root / ".appstore-review-risk.yml", document)

                with self.assertRaisesRegex(ValueError, "Invalid suppression config"):
                    scanner.scan_result(root)

    def test_symlinked_suppression_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            root = temp_root / "repo"
            root.mkdir()
            outside = temp_root / "outside.yml"
            write_text(
                outside,
                (
                    "suppressions:\n"
                    "  - id: storekit-external-purchase-language\n"
                    "    reason: External control data must not be followed.\n"
                ),
            )
            suppression = root / ".appstore-review-risk.yml"
            try:
                suppression.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"Symlinks unavailable: {error}")

            with self.assertRaisesRegex(ValueError, "symbolic links are not supported"):
                scanner.scan_result(root)

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

    def test_diff_mode_treats_untracked_files_as_working_tree_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            write_text(root / "Existing.swift", 'let copy = "Subscribe on the web"\n')
            commit_all(root, "base")
            write_text(root / "Untracked.swift", 'let copy = "Subscribe on the web"\n')

            result = scanner.diff_scan_result(root, base_ref="HEAD")
            changed_ids = {finding.id for finding in result.changed_file_findings}

            self.assertIn("Untracked.swift", result.changed_files)
            self.assertIn("storekit-external-purchase-language", changed_ids)

    def test_diff_mode_does_not_resolve_untracked_symlinks_to_changed_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            write_text(root / "Existing.swift", 'let copy = "Subscribe on the web"\n')
            commit_all(root, "base")
            link = root / "Alias.swift"
            try:
                link.symlink_to("Existing.swift")
            except OSError as error:
                self.skipTest(f"Symlinks unavailable: {error}")

            result = scanner.diff_scan_result(root, base_ref="HEAD")

            self.assertEqual(result.changed_files, [])
            self.assertNotIn(
                "storekit-external-purchase-language",
                {finding.id for finding in result.changed_file_findings},
            )

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

    def test_committed_ref_diff_does_not_consult_checkout_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, ["init"])
            source = root / "Paywall.swift"
            write_text(source, 'let copy = "Welcome"\n')
            commit_all(root, "base")
            base_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            write_text(source, 'let copy = "Subscribe on the web"\n')
            commit_all(root, "head")
            head_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            write_text(root / "Other.swift", 'let copy = "Welcome"\n')
            source.unlink()
            try:
                source.symlink_to("Other.swift")
            except OSError as error:
                self.skipTest(f"Symlinks unavailable: {error}")

            result = scanner.diff_scan_result(
                root,
                base_ref=base_ref,
                head_ref=head_ref,
            )

            self.assertIn("Paywall.swift", result.changed_files)
            self.assertIn(
                "storekit-external-purchase-language",
                {finding.id for finding in result.new_findings},
            )

    def test_git_archive_extraction_skips_symbolic_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            root = temp_root / "repo"
            root.mkdir()
            run_git(root, ["init"])
            link = root / "Leaked.swift"
            try:
                link.symlink_to("../Outside.swift")
            except OSError as error:
                self.skipTest(f"Symlinks unavailable: {error}")
            commit_all(root, "base")
            destination = temp_root / "archive"
            destination.mkdir()

            scanner.extract_git_archive(root, "HEAD", destination)

            self.assertFalse((destination / "Leaked.swift").is_symlink())
            self.assertFalse((destination / "Leaked.swift").exists())

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

    def test_openstep_synchronized_groups_scope_only_the_submitted_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, fixture_pbxproj_with_synchronized_groups())
            write_text(root / "App" / "AppView.swift", "import SwiftUI\nlet title = \"Home\"\n")
            write_text(root / "App" / "Excluded.swift", 'let copy = "Subscribe on the web"\n')
            write_text(root / "Admin" / "AdminView.swift", 'let copy = "Subscribe on the web"\n')

            app_result = scanner.scan_result(root, submitted_target="SubmittedApp")
            admin_result = scanner.scan_result(root, submitted_target="AdminApp")
            app_membership = next(item for item in app_result.target_memberships if item.target == "SubmittedApp")

            self.assertEqual(app_result.scoped_target, "SubmittedApp")
            self.assertEqual(app_membership.files, ["App/AppView.swift"])
            self.assertNotIn("storekit-external-purchase-language", {finding.id for finding in app_result.findings})
            self.assertIn("storekit-external-purchase-language", {finding.id for finding in admin_result.findings})

    def test_xml_synchronized_groups_scope_only_the_submitted_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_xml_project(root, fixture_xml_pbx_objects_with_synchronized_groups())
            write_text(root / "App" / "AppView.swift", "import SwiftUI\nlet title = \"Home\"\n")
            write_text(root / "App" / "Excluded.swift", 'let copy = "Subscribe on the web"\n')
            write_text(root / "Admin" / "AdminView.swift", 'let copy = "Subscribe on the web"\n')

            app_result = scanner.scan_result(root, submitted_target="XmlApp")
            admin_result = scanner.scan_result(root, submitted_target="XmlAdmin")
            app_membership = next(item for item in app_result.target_memberships if item.target == "XmlApp")

            self.assertEqual(app_result.scoped_target, "XmlApp")
            self.assertEqual(app_membership.files, ["App/AppView.swift"])
            self.assertNotIn("storekit-external-purchase-language", {finding.id for finding in app_result.findings})
            self.assertIn("storekit-external-purchase-language", {finding.id for finding in admin_result.findings})

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

    def test_openstep_generated_info_plist_usage_keys_are_target_scoped(self):
        generated_settings = " ".join(
            [
                'INFOPLIST_KEY_NSCameraUsageDescription = "Capture profile photos.";',
                'INFOPLIST_KEY_NSCalendarsFullAccessUsageDescription = "Add events to your calendar.";',
                'INFOPLIST_KEY_NSUserTrackingUsageDescription = "Measure advertising performance.";',
            ]
        )
        expected_missing_ids = {
            "permissions-missing-nscamerausagedescription",
            "permissions-missing-"
            + scanner.slugify(
                "NSCalendarsUsageDescription or "
                "NSCalendarsFullAccessUsageDescription or "
                "NSCalendarsWriteOnlyAccessUsageDescription"
            ),
            "tracking-missing-nsusertrackingusagedescription",
        }

        for setting_owner in ("SubmittedApp", "AdminApp"):
            with self.subTest(setting_owner=setting_owner), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_project(
                    root,
                    fixture_pbxproj_with_generated_info_plist_settings(
                        app_settings=generated_settings if setting_owner == "SubmittedApp" else "",
                        admin_settings=generated_settings if setting_owner == "AdminApp" else "",
                    ),
                )
                write_text(
                    root / "App" / "AppView.swift",
                    """
                    import AppTrackingTransparency
                    import AVFoundation
                    import EventKit

                    let camera = AVCaptureDevice.default(for: .video)
                    let eventStore = EKEventStore()
                    ATTrackingManager.requestTrackingAuthorization { _ in }
                    """,
                )
                write_text(root / "Admin" / "AdminView.swift", "import SwiftUI\n")

                result = scanner.scan_result(root, submitted_target="SubmittedApp")
                finding_ids = {finding.id for finding in result.findings}

                if setting_owner == "SubmittedApp":
                    self.assertTrue(expected_missing_ids.isdisjoint(finding_ids))
                else:
                    self.assertTrue(expected_missing_ids <= finding_ids)

    def test_openstep_generated_info_plist_keys_must_exist_in_every_configuration(self):
        generated_settings = " ".join(
            [
                'INFOPLIST_KEY_NSCameraUsageDescription = "Capture profile photos.";',
                'INFOPLIST_KEY_NSUserTrackingUsageDescription = "Measure advertising performance.";',
            ]
        )
        expected_missing_ids = {
            "permissions-missing-nscamerausagedescription",
            "tracking-missing-nsusertrackingusagedescription",
        }

        release_settings_by_case = {
            "missing": "",
            "empty": (
                'INFOPLIST_KEY_NSCameraUsageDescription = ""; '
                'INFOPLIST_KEY_NSUserTrackingUsageDescription = "";'
            ),
            "valid": generated_settings,
        }
        for release_case, release_settings in release_settings_by_case.items():
            with self.subTest(release_case=release_case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_project(
                    root,
                    fixture_pbxproj_with_generated_info_plist_settings(
                        app_settings=generated_settings,
                        app_release_settings=release_settings,
                    ),
                )
                write_text(
                    root / "App" / "AppView.swift",
                    """
                    import AppTrackingTransparency
                    import AVFoundation

                    let camera = AVCaptureDevice.default(for: .video)
                    ATTrackingManager.requestTrackingAuthorization { _ in }
                    """,
                )
                write_text(root / "Admin" / "AdminView.swift", "import SwiftUI\n")

                result = scanner.scan_result(root, submitted_target="SubmittedApp")
                finding_ids = {finding.id for finding in result.findings}

                if release_case == "valid":
                    self.assertTrue(expected_missing_ids.isdisjoint(finding_ids))
                else:
                    self.assertTrue(expected_missing_ids <= finding_ids)

    def test_openstep_generated_info_plist_values_resolve_build_setting_references(self):
        cases = {
            "undefined": (
                "INFOPLIST_KEY_NSCameraUsageDescription = "
                "$(CAMERA_PERMISSION_DESCRIPTION);"
            ),
            "defined": (
                'CAMERA_PERMISSION_DESCRIPTION = "Capture profile photos."; '
                "INFOPLIST_KEY_NSCameraUsageDescription = "
                "$(CAMERA_PERMISSION_DESCRIPTION);"
            ),
        }
        for case, settings in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_project(
                    root,
                    fixture_pbxproj_with_generated_info_plist_settings(
                        app_settings=settings,
                    ),
                )
                write_text(
                    root / "App" / "AppView.swift",
                    "import AVFoundation\nlet camera = AVCaptureDevice.default(for: .video)\n",
                )
                write_text(root / "Admin" / "AdminView.swift", "import SwiftUI\n")

                result = scanner.scan_result(root, submitted_target="SubmittedApp")
                finding_ids = {finding.id for finding in result.findings}

                if case == "defined":
                    self.assertNotIn("permissions-missing-nscamerausagedescription", finding_ids)
                else:
                    self.assertIn("permissions-missing-nscamerausagedescription", finding_ids)

    def test_xml_generated_info_plist_usage_keys_are_target_scoped(self):
        generated_settings = {
            "INFOPLIST_KEY_NSCameraUsageDescription": "Capture profile photos.",
            "INFOPLIST_KEY_NSCalendarsFullAccessUsageDescription": "Add events to your calendar.",
            "INFOPLIST_KEY_NSUserTrackingUsageDescription": "Measure advertising performance.",
        }
        expected_missing_ids = {
            "permissions-missing-nscamerausagedescription",
            "permissions-missing-"
            + scanner.slugify(
                "NSCalendarsUsageDescription or "
                "NSCalendarsFullAccessUsageDescription or "
                "NSCalendarsWriteOnlyAccessUsageDescription"
            ),
            "tracking-missing-nsusertrackingusagedescription",
        }

        for setting_owner in ("XmlApp", "XmlAppTests"):
            with self.subTest(setting_owner=setting_owner), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                objects = fixture_xml_pbx_objects()
                config_id = "CONFIG_APP" if setting_owner == "XmlApp" else "CONFIG_TEST"
                objects[config_id]["buildSettings"].update(generated_settings)
                write_xml_project(root, objects)
                write_text(
                    root / "App" / "AppView.swift",
                    """
                    import AppTrackingTransparency
                    import AVFoundation
                    import EventKit

                    let camera = AVCaptureDevice.default(for: .video)
                    let eventStore = EKEventStore()
                    ATTrackingManager.requestTrackingAuthorization { _ in }
                    """,
                )
                write_text(root / "Tests" / "AppTests.swift", "import XCTest\n")

                result = scanner.scan_result(root, submitted_target="XmlApp")
                finding_ids = {finding.id for finding in result.findings}

                if setting_owner == "XmlApp":
                    self.assertTrue(expected_missing_ids.isdisjoint(finding_ids))
                else:
                    self.assertTrue(expected_missing_ids <= finding_ids)

    def test_xml_generated_info_plist_keys_must_exist_in_every_configuration(self):
        generated_settings = {
            "INFOPLIST_KEY_NSCameraUsageDescription": "Capture profile photos.",
            "INFOPLIST_KEY_NSUserTrackingUsageDescription": "Measure advertising performance.",
        }
        expected_missing_ids = {
            "permissions-missing-nscamerausagedescription",
            "tracking-missing-nsusertrackingusagedescription",
        }

        for release_case in ("missing", "empty", "valid"):
            with self.subTest(release_case=release_case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                objects = fixture_xml_pbx_objects()
                objects["CONFIG_APP"]["name"] = "Debug"
                objects["CONFIG_APP"]["buildSettings"].update(generated_settings)
                release_settings = dict(objects["CONFIG_APP"]["buildSettings"])
                if release_case == "missing":
                    for key in generated_settings:
                        release_settings.pop(key)
                elif release_case == "empty":
                    for key in generated_settings:
                        release_settings[key] = ""
                objects["CONFIG_APP_RELEASE"] = {
                    "isa": "XCBuildConfiguration",
                    "name": "Release",
                    "buildSettings": release_settings,
                }
                objects["CONFIG_LIST_APP"]["buildConfigurations"].append("CONFIG_APP_RELEASE")
                write_xml_project(root, objects)
                write_text(
                    root / "App" / "AppView.swift",
                    """
                    import AppTrackingTransparency
                    import AVFoundation

                    let camera = AVCaptureDevice.default(for: .video)
                    ATTrackingManager.requestTrackingAuthorization { _ in }
                    """,
                )
                write_text(root / "Tests" / "AppTests.swift", "import XCTest\n")

                result = scanner.scan_result(root, submitted_target="XmlApp")
                finding_ids = {finding.id for finding in result.findings}

                if release_case == "valid":
                    self.assertTrue(expected_missing_ids.isdisjoint(finding_ids))
                else:
                    self.assertTrue(expected_missing_ids <= finding_ids)

    def test_xml_generated_info_plist_values_resolve_build_setting_references(self):
        for case in ("undefined", "defined"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                objects = fixture_xml_pbx_objects()
                settings = objects["CONFIG_APP"]["buildSettings"]
                settings["INFOPLIST_KEY_NSCameraUsageDescription"] = (
                    "$(CAMERA_PERMISSION_DESCRIPTION)"
                )
                if case == "defined":
                    settings["CAMERA_PERMISSION_DESCRIPTION"] = "Capture profile photos."
                write_xml_project(root, objects)
                write_text(
                    root / "App" / "AppView.swift",
                    "import AVFoundation\nlet camera = AVCaptureDevice.default(for: .video)\n",
                )
                write_text(root / "Tests" / "AppTests.swift", "import XCTest\n")

                result = scanner.scan_result(root, submitted_target="XmlApp")
                finding_ids = {finding.id for finding in result.findings}

                if case == "defined":
                    self.assertNotIn("permissions-missing-nscamerausagedescription", finding_ids)
                else:
                    self.assertIn("permissions-missing-nscamerausagedescription", finding_ids)

    def test_system_photo_pickers_do_not_imply_direct_photo_library_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, "SDKROOT = iphoneos; TARGETED_DEVICE_FAMILY = 1;")
            source = root / "Sources" / "PhotoPicker.swift"
            write_text(
                source,
                """
                import PhotosUI

                PhotosPicker(selection: $selection, matching: .images)
                let configuration = PHPickerConfiguration(photoLibrary: .shared())
                let controller = PHPickerViewController(configuration: configuration)
                """,
            )

            picker_result = scanner.scan_result(root)
            picker_ids = {finding.id for finding in picker_result.findings}
            self.assertNotIn("permissions-missing-nsphotolibraryusagedescription", picker_ids)

            write_text(
                source,
                """
                import Photos

                PHPhotoLibrary.requestAuthorization { _ in }
                """,
            )
            direct_result = scanner.scan_result(root)
            direct_ids = {finding.id for finding in direct_result.findings}
            self.assertIn("permissions-missing-nsphotolibraryusagedescription", direct_ids)

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

    def test_broken_symlink_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / "Broken.swift"
            try:
                link.symlink_to(root / "Missing.swift")
            except OSError as error:
                self.skipTest(f"Symlinks unavailable: {error}")

            self.assertEqual(list(scanner.iter_files(root)), [])
            self.assertEqual(scanner.scan_result(root).findings, [])

    def test_unreadable_text_file_is_reported_as_a_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "App.swift", "import SwiftUI\n")
            with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
                result = scanner.scan_result(root)

            self.assertTrue(any("Skipped unreadable file `App.swift`" in note for note in result.notes))


if __name__ == "__main__":
    unittest.main()
