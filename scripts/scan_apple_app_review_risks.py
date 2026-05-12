#!/usr/bin/env python3
"""Heuristic static scanner for Apple App Review risk surfaces."""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SKIP_DIRS = {
    ".build",
    ".git",
    ".swiftpm",
    "Build",
    "DerivedData",
    "Pods",
    "build",
    "node_modules",
}

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".html",
    ".js",
    ".jsx",
    ".json",
    ".m",
    ".mm",
    ".plist",
    ".strings",
    ".swift",
    ".ts",
    ".tsx",
    ".xcent",
    ".xcconfig",
    ".xcprivacy",
    ".xml",
}

PLATFORM_FOCUS: dict[str, list[str]] = {
    "iOS": ["privacy strings", "ATT", "StoreKit", "account deletion", "UGC", "location", "background modes", "touch interaction"],
    "iPadOS": ["adaptive layouts", "multitasking", "keyboard and pointer support", "privacy strings", "StoreKit", "account deletion"],
    "macOS": ["sandboxing", "hardened runtime/notarization", "file access", "menu bar", "window behavior", "helper tools"],
    "watchOS": ["companion dependencies", "HealthKit", "background refresh", "workouts", "complications", "small-screen interaction"],
    "tvOS": ["remote/focus navigation", "media playback", "subscriptions", "top shelf", "account login ergonomics"],
    "visionOS": ["spatial interaction", "comfort", "immersive spaces", "privacy", "accessibility", "window scale"],
}

PLATFORM_SIGNAL_PATTERNS: dict[str, list[str]] = {
    "iOS": [r"\biphoneos\b", r"\biphonesimulator\b", r"\bUIKit\b", r"\bUIApplication\b"],
    "iPadOS": [r"TARGETED_DEVICE_FAMILY\s*=\s*\"?[^\";]*2", r"\bUISplitViewController\b", r"\bNavigationSplitView\b"],
    "macOS": [r"\bmacosx\b", r"\bAppKit\b", r"\bNSApplication\b", r"com\.apple\.security\.app-sandbox"],
    "watchOS": [r"\bwatchos\b", r"\bwatchsimulator\b", r"\bWatchKit\b", r"\bWKApplication\b"],
    "tvOS": [r"\bappletvos\b", r"\bappletvsimulator\b", r"\bTVUIKit\b", r"\bTVApplicationController\b"],
    "visionOS": [r"\bxros\b", r"\bxrsimulator\b", r"\bvisionOS\b", r"\bRealityView\b", r"\bImmersiveSpace\b"],
}

DEVICE_FAMILY_PLATFORMS = {
    1: "iOS",
    2: "iPadOS",
}

PERMISSION_CLUES: dict[str, list[str]] = {
    "NSCameraUsageDescription": [r"\bAVCaptureDevice\b", r"\bUIImagePickerController\b.*camera", r"\.camera\b"],
    "NSMicrophoneUsageDescription": [r"\bAVAudioRecorder\b", r"\brequestRecordPermission\b", r"\bAVCaptureDevice\b.*audio"],
    "NSPhotoLibraryUsageDescription": [r"\bPHPhotoLibrary\b", r"\bPhotosPicker\b", r"\bPHPickerViewController\b", r"photoLibrary"],
    "NSPhotoLibraryAddUsageDescription": [r"\bPHPhotoLibrary\b.*performChanges", r"\bsaveToPhoto", r"\bUIImageWriteToSavedPhotosAlbum\b"],
    "NSLocationWhenInUseUsageDescription": [r"\bCLLocationManager\b", r"\bCoreLocation\b", r"\brequestWhenInUseAuthorization\b"],
    "NSLocationAlwaysAndWhenInUseUsageDescription": [r"\brequestAlwaysAuthorization\b", r"\ballowsBackgroundLocationUpdates\b"],
    "NSContactsUsageDescription": [r"\bCNContactStore\b", r"\bContacts\b"],
    "NSCalendarsUsageDescription": [r"\bEKEventStore\b", r"\bEKEvent\b"],
    "NSRemindersUsageDescription": [r"\bEKReminder\b"],
    "NSBluetoothAlwaysUsageDescription": [r"\bCBCentralManager\b", r"\bCBPeripheralManager\b", r"\bCoreBluetooth\b"],
    "NSHealthShareUsageDescription": [r"\bHKHealthStore\b", r"\bHealthKit\b"],
    "NSHealthUpdateUsageDescription": [r"\bHKQuantityType\b", r"\bsaveObject\b"],
    "NSHomeKitUsageDescription": [r"\bHMHomeManager\b", r"\bHomeKit\b"],
    "NSFaceIDUsageDescription": [r"\bdeviceOwnerAuthenticationWithBiometrics\b", r"\bLAPolicy\.deviceOwnerAuthenticationWithBiometrics\b"],
    "NSSpeechRecognitionUsageDescription": [r"\bSFSpeechRecognizer\b", r"\bSpeech\b"],
    "NSMotionUsageDescription": [r"\bCMMotionManager\b", r"\bCoreMotion\b", r"\bCMPedometer\b"],
    "NSNearbyInteractionUsageDescription": [r"\bNISession\b", r"\bNearbyInteraction\b"],
    "NSLocalNetworkUsageDescription": [r"\bNWBrowser\b", r"\bNetServiceBrowser\b", r"\bNSNetService\b"],
    "NFCReaderUsageDescription": [r"\bNFCNDEFReaderSession\b", r"\bCoreNFC\b"],
    "NSAppleMusicUsageDescription": [r"\bMPMediaLibrary\b", r"\bSKCloudServiceController\b"],
    "NSSiriUsageDescription": [r"\bINPreferences\b.*requestSiriAuthorization", r"\bIntents\b"],
}

PERMISSION_ALTERNATIVE_KEYS: dict[str, list[str]] = {
    "NSBluetoothAlwaysUsageDescription": ["NSBluetoothPeripheralUsageDescription"],
    "NSCalendarsUsageDescription": ["NSCalendarsFullAccessUsageDescription", "NSCalendarsWriteOnlyAccessUsageDescription"],
    "NSLocationAlwaysAndWhenInUseUsageDescription": ["NSLocationAlwaysUsageDescription"],
    "NSRemindersUsageDescription": ["NSRemindersFullAccessUsageDescription"],
}

REQUIRED_REASON_CLUES: dict[str, list[str]] = {
    "User defaults": [r"\bUserDefaults\b", r"\bNSUserDefaults\b"],
    "File timestamps": [r"\bcontentModificationDateKey\b", r"\bcreationDateKey\b", r"\battributesOfItem\b", r"\bgetattrlist\b"],
    "Disk space": [r"\bvolumeAvailableCapacity", r"\bvolumeTotalCapacity", r"\bsystemFreeSize\b", r"\bstatfs\b"],
    "System boot time": [r"\bsystemUptime\b", r"\bmach_absolute_time\b", r"\bCACurrentMediaTime\b"],
}

SENSITIVE_ENTITLEMENTS: dict[str, tuple[str, str]] = {
    "com.apple.developer.applesignin": ("Sign in with Apple", "Confirm parity with other login options and App Store metadata."),
    "com.apple.developer.associated-domains": ("Associated Domains", "Verify universal links, web credentials, and external account links are intentional."),
    "com.apple.developer.healthkit": ("HealthKit", "Verify health purpose strings, privacy policy, and visible health feature behavior."),
    "com.apple.developer.homekit": ("HomeKit", "Verify HomeKit feature behavior and purpose strings."),
    "com.apple.developer.icloud-container-identifiers": ("iCloud", "Verify iCloud storage behavior and privacy disclosures."),
    "com.apple.developer.in-app-payments": ("Apple Pay", "Verify Apple Pay use is for physical goods or compliant services."),
    "com.apple.developer.networking.HotspotConfiguration": ("Hotspot Configuration", "Verify restricted networking entitlement approval and review notes."),
    "com.apple.developer.networking.multicast": ("Multicast Networking", "Verify entitlement approval and user-facing local network behavior."),
    "com.apple.developer.networking.networkextension": ("Network Extension", "Verify restricted entitlement approval and VPN/networking review notes."),
    "com.apple.developer.storekit.external-link.account": ("StoreKit External Account Link", "Verify entitlement approval, regions, link copy, and StoreKit guidance."),
    "com.apple.developer.storekit.external-purchase": ("StoreKit External Purchase", "Verify entitlement approval, regions, disclosure flow, and current StoreKit guidance."),
    "com.apple.developer.storekit.external-purchase-link": ("StoreKit External Purchase Link", "Verify entitlement approval, eligible URLs, regions, and current StoreKit guidance."),
    "com.apple.developer.storekit.external-purchase-link-streaming": ("StoreKit External Purchase Link Streaming", "Verify qualifying app type, entitlement approval, and current StoreKit guidance."),
    "com.apple.developer.usernotifications.critical-alerts": ("Critical Alerts", "Verify entitlement approval and critical alert justification."),
    "com.apple.developer.family-controls": ("Family Controls", "Verify restricted entitlement approval and Screen Time review notes."),
}

EXTERNAL_PURCHASE_PATTERNS = [
    r"subscribe on (the )?web",
    r"purchase on (our|the) website",
    r"external purchase",
    r"checkout session",
    r"billing portal",
    r"stripe checkout",
    r"manage subscription.*website",
]

STOREKIT_PATTERNS = [
    r"\bimport StoreKit\b",
    r"\bProduct\.products\b",
    r"\bpurchase\(",
    r"\bTransaction\.currentEntitlements\b",
    r"\bSKPaymentQueue\b",
    r"\bSubscriptionStoreView\b",
]

RESTORE_PATTERNS = [
    r"\brestore\b",
    r"\bAppStore\.sync\b",
    r"\bcurrentEntitlements\b",
    r"\brestoreCompletedTransactions\b",
]

SOCIAL_LOGIN_PATTERNS = [
    r"\bGoogleSignIn\b",
    r"\bGIDSignIn\b",
    r"\bFBSDKLoginKit\b",
    r"\bFacebookLogin\b",
    r"\bsign in with google\b",
    r"\bsign in with facebook\b",
]

APPLE_SIGN_IN_PATTERNS = [
    r"\bASAuthorizationAppleIDProvider\b",
    r"\bSignInWithAppleButton\b",
    r"com\.apple\.developer\.applesignin",
]

ACCOUNT_PATTERNS = [
    r"\bcreate account\b",
    r"\bsign up\b",
    r"\bsignup\b",
    r"\bregister\b",
    r"\bAuth\.auth\b",
    r"\blogin\b",
]

DELETE_ACCOUNT_PATTERNS = [
    r"\bdelete account\b",
    r"\bdelete my account\b",
    r"\baccount deletion\b",
    r"\bclose account\b",
]

UGC_PATTERNS = [
    r"\bcomment\b",
    r"\bpost\b",
    r"\bupload\b",
    r"\bprofile\b",
    r"\bfollow\b",
    r"\bmessage\b",
    r"\bchat\b",
    r"\breview\b",
    r"\buser generated\b",
]

MODERATION_PATTERNS = [
    r"\breport\b",
    r"\bblock\b",
    r"\bmoderate\b",
    r"\bflag\b",
    r"\babuse\b",
    r"\bmute\b",
]

PLACEHOLDER_PATTERNS = [
    r"\bTODO\b",
    r"\bFIXME\b",
    r"\bLorem ipsum\b",
    r"example\.com",
    r"localhost",
    r"127\.0\.0\.1",
    r"\bplaceholder\b",
    r"\bcoming soon\b",
]

PRIVATE_API_PATTERNS = [
    r"NSClassFromString\(@?\"_",
    r"NSSelectorFromString\(@?\"_",
    r"performSelector\(",
    r"\b_private\b",
]

VAGUE_USAGE_WORDS = {
    "",
    "access required",
    "app requires access",
    "needed",
    "needed for app functionality",
    "required",
    "this app needs access",
    "we need access",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    confidence: str
    evidence: list[str]
    recommendation: str


@dataclass
class TargetPlatform:
    platform: str
    confidence: str
    evidence: list[str]
    guideline_focus: list[str]


@dataclass
class ScanResult:
    target_platforms: list[TargetPlatform]
    findings: list[Finding]


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    if path.stat().st_size > 2_000_000:
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def load_plist(path: Path) -> Any | None:
    try:
        with path.open("rb") as handle:
            return plistlib.load(handle)
    except Exception:
        return None


def plist_has_key(plists: list[tuple[Path, Any]], key: str) -> bool:
    return any(isinstance(data, dict) and key in data for _, data in plists)


def plist_key_values(plists: list[tuple[Path, Any]], key: str, root: Path) -> list[str]:
    values: list[str] = []
    for path, data in plists:
        if isinstance(data, dict) and key in data:
            values.append(f"{rel(path, root)}:{key}={data[key]!r}")
    return values


def text_hits(files: list[Path], patterns: list[str], root: Path, max_hits: int = 8) -> list[str]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    hits: list[str] = []
    for path in files:
        if path.suffix not in TEXT_EXTENSIONS:
            continue
        text = read_text(path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in compiled):
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                hits.append(f"{rel(path, root)}:{line_number}: {snippet}")
                if len(hits) >= max_hits:
                    return hits
    return hits


def all_text_has(files: list[Path], patterns: list[str], root: Path) -> bool:
    return bool(text_hits(files, patterns, root, max_hits=1))


def is_vague_usage_value(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    normalized = re.sub(r"\s+", " ", value.strip().lower())
    if len(normalized) < 12:
        return True
    if normalized in VAGUE_USAGE_WORDS:
        return True
    return any(token in normalized for token in ("todo", "placeholder", "lorem ipsum"))


def add(
    findings: list[Finding],
    severity: str,
    category: str,
    title: str,
    confidence: str,
    evidence: list[str],
    recommendation: str,
) -> None:
    findings.append(Finding(severity, category, title, confidence, evidence, recommendation))


def detect_target_platforms(root: Path, files: list[Path], parsed_plists: list[tuple[Path, Any]]) -> list[TargetPlatform]:
    signals: dict[str, list[str]] = {platform: [] for platform in PLATFORM_FOCUS}
    strong_platforms: set[str] = set()

    def add_signal(platform: str, evidence: str, strong: bool = False) -> None:
        if platform not in signals:
            return
        if evidence not in signals[platform] and len(signals[platform]) < 8:
            signals[platform].append(evidence)
        if strong:
            strong_platforms.add(platform)

    for path, data in parsed_plists:
        if not isinstance(data, dict):
            continue
        device_families = data.get("UIDeviceFamily")
        if isinstance(device_families, int):
            device_families = [device_families]
        if isinstance(device_families, list):
            for family in device_families:
                platform = DEVICE_FAMILY_PLATFORMS.get(family)
                if platform:
                    add_signal(platform, f"{rel(path, root)}:UIDeviceFamily contains {family}", strong=True)
        bundle_package_type = data.get("CFBundlePackageType")
        if bundle_package_type == "APPL":
            if "WKWatchKitApp" in data:
                add_signal("watchOS", f"{rel(path, root)}:WKWatchKitApp", strong=True)
            if "UIApplicationSceneManifest" in data or "UISupportedInterfaceOrientations" in data:
                add_signal("iOS", f"{rel(path, root)}:{bundle_package_type}", strong=False)

    compiled = {
        platform: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        for platform, patterns in PLATFORM_SIGNAL_PATTERNS.items()
    }
    candidate_suffixes = {".pbxproj", ".xcconfig", ".plist", ".entitlements", ".xcent", ".swift", ".m", ".mm", ".h"}
    for path in files:
        if path.suffix not in candidate_suffixes:
            continue
        text = read_text(path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            for platform, patterns in compiled.items():
                for pattern in patterns:
                    if pattern.search(stripped):
                        strong = any(token in stripped for token in ("SDKROOT", "SUPPORTED_PLATFORMS", "TARGETED_DEVICE_FAMILY"))
                        snippet = stripped[:140]
                        add_signal(platform, f"{rel(path, root)}:{line_number}: {snippet}", strong=strong)
                        break

    targets: list[TargetPlatform] = []
    for platform in PLATFORM_FOCUS:
        evidence = signals[platform]
        if not evidence:
            continue
        confidence = "high" if platform in strong_platforms else "medium"
        targets.append(
            TargetPlatform(
                platform=platform,
                confidence=confidence,
                evidence=evidence,
                guideline_focus=PLATFORM_FOCUS[platform],
            )
        )
    return targets


def scan_result(root: Path) -> ScanResult:
    files = list(iter_files(root))
    text_files = [path for path in files if path.suffix in TEXT_EXTENSIONS]
    plist_files = [path for path in files if path.suffix in {".plist", ".entitlements", ".xcprivacy", ".xcent"}]
    parsed_plists = [(path, load_plist(path)) for path in plist_files]
    parsed_plists = [(path, data) for path, data in parsed_plists if data is not None]
    info_plists = [
        (path, data)
        for path, data in parsed_plists
        if path.name == "Info.plist" or (isinstance(data, dict) and any(key.startswith("NS") for key in data))
    ]
    privacy_manifests = [(path, data) for path, data in parsed_plists if path.name == "PrivacyInfo.xcprivacy"]
    entitlement_plists = [(path, data) for path, data in parsed_plists if path.suffix in {".entitlements", ".xcent"}]
    target_platforms = detect_target_platforms(root, files, parsed_plists)
    findings: list[Finding] = []

    has_xcode_artifact = any(path.name == "project.pbxproj" or path.suffix == ".swift" for path in files)
    if has_xcode_artifact and not privacy_manifests:
        add(
            findings,
            "MEDIUM",
            "Privacy",
            "No PrivacyInfo.xcprivacy file found",
            "medium",
            ["No PrivacyInfo.xcprivacy discovered in the scanned tree."],
            "Verify whether the app or bundled SDKs collect data or use required-reason APIs. Add valid privacy manifests where required and align App Privacy answers.",
        )

    for usage_key, patterns in PERMISSION_CLUES.items():
        hits = text_hits(text_files, patterns, root, max_hits=4)
        accepted_keys = [usage_key, *PERMISSION_ALTERNATIVE_KEYS.get(usage_key, [])]
        values = []
        for accepted_key in accepted_keys:
            values.extend(plist_key_values(info_plists, accepted_key, root))
        if hits and not values:
            key_label = " or ".join(accepted_keys)
            add(
                findings,
                "HIGH",
                "Permissions",
                f"Potential protected-resource use without {key_label}",
                "medium",
                hits,
                f"Add a specific {key_label} purpose string to the app target Info.plist or remove the protected-resource code path.",
            )
        for value in values:
            raw_value = value.split("=", 1)[-1]
            if is_vague_usage_value(raw_value.strip("'")):
                add(
                    findings,
                    "MEDIUM",
                    "Permissions",
                    f"Vague or invalid {usage_key}",
                    "medium",
                    [value],
                    "Replace the purpose string with a specific user-facing explanation tied to the visible feature that uses the protected resource.",
                )

    att_hits = text_hits(text_files, [r"\bATTrackingManager\b", r"\bAppTrackingTransparency\b", r"\bASIdentifierManager\b", r"\badvertisingIdentifier\b"], root)
    if att_hits and not plist_has_key(info_plists, "NSUserTrackingUsageDescription"):
        add(
            findings,
            "HIGH",
            "Tracking",
            "Tracking or IDFA APIs found without NSUserTrackingUsageDescription",
            "medium",
            att_hits,
            "Add a clear tracking usage description, verify ATT prompt timing, and align App Privacy answers with actual tracking behavior.",
        )

    required_reason_hits: list[str] = []
    for category, patterns in REQUIRED_REASON_CLUES.items():
        hits = text_hits(text_files, patterns, root, max_hits=3)
        if hits:
            required_reason_hits.extend([f"{category}: {hit}" for hit in hits])
    manifest_declares_reasons = any(
        isinstance(data, dict) and "NSPrivacyAccessedAPITypes" in data for _, data in privacy_manifests
    )
    if required_reason_hits and not manifest_declares_reasons:
        add(
            findings,
            "MEDIUM",
            "Privacy",
            "Potential required-reason API use not declared in privacy manifest",
            "low",
            required_reason_hits[:8],
            "Inspect these APIs against Apple's required-reason API categories and add NSPrivacyAccessedAPITypes entries with approved reasons when applicable.",
        )

    for path, data in entitlement_plists:
        if not isinstance(data, dict):
            continue
        for key, (label, recommendation) in SENSITIVE_ENTITLEMENTS.items():
            if key in data:
                severity = "HIGH" if "external-purchase" in key or "external-link" in key else "MEDIUM"
                add(
                    findings,
                    severity,
                    "Entitlements",
                    f"Review-sensitive entitlement: {label}",
                    "high",
                    [f"{rel(path, root)}:{key}={data[key]!r}"],
                    recommendation,
                )

    for key in ("SKExternalPurchaseLink", "SKExternalPurchaseMultiLink"):
        values = plist_key_values(info_plists, key, root)
        if values:
            add(
                findings,
                "HIGH",
                "StoreKit",
                f"{key} configured",
                "high",
                values,
                "Verify external purchase entitlement approval, eligible regions/URLs, disclosure flow, and current StoreKit external purchase guidance.",
            )

    external_purchase_hits = text_hits(text_files, EXTERNAL_PURCHASE_PATTERNS, root)
    if external_purchase_hits:
        add(
            findings,
            "HIGH",
            "StoreKit",
            "External purchase or web billing language found",
            "medium",
            external_purchase_hits,
            "Confirm the app is not steering digital purchases outside StoreKit unless it has the correct entitlement, storefront eligibility, disclosure flow, and review notes.",
        )

    storekit_hits = text_hits(text_files, STOREKIT_PATTERNS, root, max_hits=5)
    if storekit_hits and not all_text_has(text_files, RESTORE_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "StoreKit",
            "StoreKit usage found without obvious restore/current entitlement path",
            "low",
            storekit_hits,
            "Verify the UI exposes purchase restoration or current entitlement recovery where appropriate, and include subscription review notes.",
        )

    social_hits = text_hits(text_files, SOCIAL_LOGIN_PATTERNS, root)
    if social_hits and not all_text_has(text_files, APPLE_SIGN_IN_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "Authentication",
            "Third-party/social login found without obvious Sign in with Apple",
            "medium",
            social_hits,
            "Verify whether Sign in with Apple parity is required for the login options offered, or document the applicable exception.",
        )

    account_hits = text_hits(text_files, ACCOUNT_PATTERNS, root, max_hits=6)
    if account_hits and not all_text_has(text_files, DELETE_ACCOUNT_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "Accounts",
            "Account creation/login clues found without obvious account deletion flow",
            "medium",
            account_hits,
            "Verify the app exposes an in-app account deletion path or a clearly compliant deletion flow, and document it in review notes if not obvious.",
        )

    ugc_hits = text_hits(text_files, UGC_PATTERNS, root, max_hits=6)
    if ugc_hits and not all_text_has(text_files, MODERATION_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "User-generated content",
            "UGC/social clues found without obvious reporting or blocking flow",
            "low",
            ugc_hits,
            "Inspect the actual product behavior for moderation, reporting, blocking, abuse handling, filtering, and reviewer-accessible test content.",
        )

    background_values = plist_key_values(info_plists, "UIBackgroundModes", root)
    if background_values:
        add(
            findings,
            "MEDIUM",
            "Background behavior",
            "Background modes enabled",
            "high",
            background_values,
            "Verify each background mode maps to a visible user-facing feature and is explained in review notes when the reviewer may not trigger it naturally.",
        )

    private_hits = text_hits(text_files, PRIVATE_API_PATTERNS, root)
    if private_hits:
        add(
            findings,
            "HIGH",
            "Private APIs",
            "Potential private API or dynamic private selector usage",
            "low",
            private_hits,
            "Inspect these calls carefully. Remove private API usage or prove the dynamic selector is public and necessary.",
        )

    placeholder_hits = text_hits(text_files, PLACEHOLDER_PATTERNS, root, max_hits=10)
    if placeholder_hits:
        add(
            findings,
            "LOW",
            "App completeness",
            "Placeholder, local, or unfinished text found",
            "low",
            placeholder_hits,
            "Review whether these strings can appear in the submitted app, metadata, URLs, or review-visible flows. Remove unfinished content before submission.",
        )

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda finding: (severity_order.get(finding.severity, 9), finding.category, finding.title))
    return ScanResult(target_platforms=target_platforms, findings=findings)


def scan(root: Path) -> list[Finding]:
    return scan_result(root).findings


def print_markdown(root: Path, result: ScanResult) -> None:
    print("# Apple App Review Risk Scan")
    print()
    print(f"Target: `{root}`")
    print()
    print("Static heuristic results. Inspect every finding manually before treating it as an App Review issue.")
    print()
    if result.target_platforms:
        print("## Likely Platform Targets")
        print()
        print("| Platform | Confidence | Guideline focus |")
        print("| --- | --- | --- |")
        for target in result.target_platforms:
            print(f"| {target.platform} | {target.confidence} | {', '.join(target.guideline_focus)} |")
        print()
        for target in result.target_platforms:
            print(f"### {target.platform} Evidence")
            print()
            for item in target.evidence:
                print(f"- `{item}`")
            print()
    else:
        print("## Likely Platform Targets")
        print()
        print("No platform target signals were found. Identify the submitted app target manually before applying platform-specific guidelines.")
        print()

    findings = result.findings
    if not findings:
        print("No obvious review-risk signals were found by the scanner.")
        return
    print("## Findings")
    print()
    print("| Severity | Category | Title | Confidence |")
    print("| --- | --- | --- | --- |")
    for finding in findings:
        print(f"| {finding.severity} | {finding.category} | {finding.title} | {finding.confidence} |")
    print()
    for finding in findings:
        print(f"## [{finding.severity}] {finding.title}")
        print()
        print(f"- Category: {finding.category}")
        print(f"- Confidence: {finding.confidence}")
        print("- Evidence:")
        for item in finding.evidence:
            print(f"  - `{item}`")
        print(f"- Recommendation: {finding.recommendation}")
        print()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Scan Apple app repositories for App Review risk signals.")
    parser.add_argument("path", type=Path, help="Path to an Apple app repository or project directory.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--fail-on", choices=("none", "high", "medium"), default="none")
    args = parser.parse_args(argv)

    root = args.path.expanduser().resolve()
    if not root.exists():
        print(f"Path does not exist: {root}", file=sys.stderr)
        return 2

    result = scan_result(root)
    if args.format == "json":
        print(json.dumps({"target": str(root), **asdict(result)}, indent=2))
    else:
        print_markdown(root, result)

    findings = result.findings
    if args.fail_on == "high" and any(finding.severity == "HIGH" for finding in findings):
        return 1
    if args.fail_on == "medium" and any(finding.severity in {"HIGH", "MEDIUM"} for finding in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
