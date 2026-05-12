#!/usr/bin/env python3
"""Heuristic static scanner for Apple App Review risk surfaces."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


SKIP_DIRS = {
    ".build",
    ".git",
    ".swiftpm",
    ".derivedData",
    ".cache",
    ".claude",
    "Build",
    "DerivedData",
    "Index.noindex",
    "Logs",
    "ModuleCache.noindex",
    "Pods",
    "SourcePackages",
    "artifacts",
    "build",
    "node_modules",
    "tmp",
    "xcuserdata",
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
    ".yml",
    ".yaml",
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
    "1": "iOS",
    "2": "iPadOS",
}

APP_PRODUCT_TYPES = {
    "APPL",
    "com.apple.product-type.application",
    "com.apple.product-type.application.tv",
    "com.apple.product-type.application.watchapp2",
}

TEST_PRODUCT_TYPES = {
    "com.apple.product-type.bundle.ui-testing",
    "com.apple.product-type.bundle.unit-test",
}

BUNDLED_PRODUCT_TYPES = {
    "com.apple.product-type.app-extension",
    "com.apple.product-type.framework",
    "com.apple.product-type.messages-extension",
    "com.apple.product-type.sticker-pack",
    "com.apple.product-type.tv-app-extension",
    "com.apple.product-type.watchkit2-extension",
    "com.apple.product-type.xpc-service",
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

REQUIRED_REASON_CLUES: dict[str, tuple[str, list[str]]] = {
    "NSPrivacyAccessedAPICategoryUserDefaults": ("User defaults", [r"\bUserDefaults\b", r"\bNSUserDefaults\b"]),
    "NSPrivacyAccessedAPICategoryFileTimestamp": ("File timestamps", [r"\bcontentModificationDateKey\b", r"\bcreationDateKey\b", r"\battributesOfItem\b", r"\bgetattrlist\b"]),
    "NSPrivacyAccessedAPICategoryDiskSpace": ("Disk space", [r"\bvolumeAvailableCapacity", r"\bvolumeTotalCapacity", r"\bsystemFreeSize\b", r"\bstatfs\b"]),
    "NSPrivacyAccessedAPICategorySystemBootTime": ("System boot time", [r"\bsystemUptime\b", r"\bmach_absolute_time\b", r"\bCACurrentMediaTime\b"]),
}

PRIVACY_COLLECTION_CLUES = [
    r"\banalytics\b",
    r"\bcrashlytics\b",
    r"\bemail\b",
    r"\bphone number\b",
    r"\badvertisingIdentifier\b",
    r"\btracking\b",
]

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
    r"\bregister account\b",
    r"\bcreateUser\b",
    r"\bcreate user\b",
    r"\bAuth\.auth\b",
    r"\blog in\b",
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
    r"\bcoming soon\b",
]

PLACEHOLDER_EXCLUDE_PATTERNS = [
    r"\.redacted\(reason:\s*\.placeholder\)",
    r"\bRedactionReasons\.placeholder\b",
]

PRIVATE_API_PATTERNS = [
    r"NSClassFromString\(@?\"_",
    r"NSSelectorFromString\(@?\"_",
    r"performSelector\(",
    r"\b_private\b",
]

ARTIFACT_PATTERNS: dict[str, list[str]] = {
    "App Store metadata and screenshots": [r"fastlane/metadata", r"screenshots?/", r"/metadata/"],
    "Review notes and demo access": [r"review[-_ ]?notes", r"demo[-_ ]?account", r"test[-_ ]?account", r"review[-_ ]?credentials"],
    "App Privacy answers": [r"privacy[-_ ]?nutrition", r"app[-_ ]?privacy", r"privacy_details", r"privacy[-_ ]?answers"],
    "Privacy policy and support URL": [r"privacy[-_ ]?policy", r"support[-_ ]?url", r"supportUrl", r"privacyUrl"],
}

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
    id: str
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
class TargetSummary:
    name: str
    bundle_identifier: str | None
    product_type: str | None
    platforms: list[str]
    sdkroot: str | None
    supported_platforms: list[str]
    targeted_device_family: list[str]
    submission_path: str
    evidence: list[str]


@dataclass
class TargetMembership:
    target: str
    product_type: str | None
    file_count: int
    files: list[str]
    evidence: list[str]


@dataclass
class ArtifactCheck:
    name: str
    status: str
    evidence: list[str]
    recommendation: str


@dataclass
class Suppression:
    finding_id: str
    reason: str


@dataclass
class ScanResult:
    target_platforms: list[TargetPlatform]
    targets: list[TargetSummary]
    target_memberships: list[TargetMembership]
    scoped_target: str | None
    findings: list[Finding]
    artifact_checks: list[ArtifactCheck]
    suppressions_applied: list[Suppression]
    notes: list[str]


def slugify(value: str) -> str:
    return re.sub(r"(^-|-$)", "", re.sub(r"[^a-z0-9]+", "-", value.lower()))


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in SKIP_DIRS and not dirname.endswith((".noindex", ".xcresult"))
        ]
        for filename in filenames:
            yield Path(dirpath) / filename


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


@lru_cache(maxsize=8192)
def read_text(path: Path) -> str:
    if path.stat().st_size > 2_000_000:
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def load_plist(path: Path) -> tuple[Any | None, str | None]:
    try:
        with path.open("rb") as handle:
            return plistlib.load(handle), None
    except Exception as error:
        return None, str(error)


def plist_has_key(plists: list[tuple[Path, Any]], key: str) -> bool:
    return any(isinstance(data, dict) and key in data for _, data in plists)


def plist_key_values(plists: list[tuple[Path, Any]], key: str, root: Path) -> list[str]:
    values: list[str] = []
    for path, data in plists:
        if isinstance(data, dict) and key in data:
            values.append(f"{rel(path, root)}:{key}={data[key]!r}")
    return values


def text_hits(
    files: list[Path],
    patterns: list[str],
    root: Path,
    max_hits: int = 8,
    exclude_patterns: list[str] | None = None,
) -> list[str]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    exclude_compiled = [re.compile(pattern, re.IGNORECASE) for pattern in exclude_patterns or []]
    hits: list[str] = []
    for path in files:
        if path.suffix not in TEXT_EXTENSIONS:
            continue
        text = read_text(path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in exclude_compiled):
                continue
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
    finding_id: str | None = None,
) -> None:
    findings.append(
        Finding(
            id=finding_id or slugify(f"{category}-{title}"),
            severity=severity,
            category=category,
            title=title,
            confidence=confidence,
            evidence=evidence,
            recommendation=recommendation,
        )
    )


def split_build_setting(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip().strip('"') for part in re.split(r"[,\s]+", value) if part.strip().strip('"')]


def has_build_setting_reference(value: str | None) -> bool:
    if not value:
        return False
    return bool(re.search(r"\$\([^)]+\)|\$\{[^}]+\}", value.strip()))


def platforms_from_settings(settings: dict[str, str]) -> list[str]:
    platforms: set[str] = set()
    sdkroot = settings.get("SDKROOT", "")
    supported = " ".join(split_build_setting(settings.get("SUPPORTED_PLATFORMS")))
    combined = f"{sdkroot} {supported}".lower()
    if "iphoneos" in combined:
        platforms.add("iOS")
    if "macosx" in combined:
        platforms.add("macOS")
    if "watchos" in combined:
        platforms.add("watchOS")
    if "appletvos" in combined:
        platforms.add("tvOS")
    if "xros" in combined:
        platforms.add("visionOS")
    for family in split_build_setting(settings.get("TARGETED_DEVICE_FAMILY")):
        platform = DEVICE_FAMILY_PLATFORMS.get(family)
        if platform:
            platforms.add(platform)
    if settings.get("SUPPORTS_MACCATALYST") == "YES":
        platforms.add("macOS")
    return sorted(platforms, key=list(PLATFORM_FOCUS).index)


def infer_submission_path(platforms: list[str], settings: dict[str, str]) -> str:
    product_type = settings.get("PRODUCT_TYPE", "")
    if product_type in TEST_PRODUCT_TYPES:
        return "Not submitted app target"
    if product_type in BUNDLED_PRODUCT_TYPES or "extension" in product_type:
        return "Bundled with containing app"
    if "macOS" in platforms and settings.get("ENABLE_HARDENED_RUNTIME") == "YES":
        return "macOS App Store or notarization"
    if platforms:
        return "App Store / TestFlight"
    return "Unknown"


def target_from_settings(name: str, settings: dict[str, str], evidence: list[str]) -> TargetSummary:
    platforms = platforms_from_settings(settings)
    return TargetSummary(
        name=name,
        bundle_identifier=settings.get("PRODUCT_BUNDLE_IDENTIFIER"),
        product_type=settings.get("PRODUCT_TYPE"),
        platforms=platforms,
        sdkroot=settings.get("SDKROOT"),
        supported_platforms=split_build_setting(settings.get("SUPPORTED_PLATFORMS")),
        targeted_device_family=split_build_setting(settings.get("TARGETED_DEVICE_FAMILY")),
        submission_path=infer_submission_path(platforms, settings),
        evidence=evidence,
    )


def parse_xcodebuild_list_json(raw: str) -> tuple[list[str], list[str]]:
    data = json.loads(raw)
    container = data.get("workspace") or data.get("project") or {}
    return list(container.get("schemes", [])), list(container.get("targets", []))


def parse_show_build_settings_json(raw: str) -> list[TargetSummary]:
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("targets", [data])
    targets: list[TargetSummary] = []
    if not isinstance(data, list):
        return targets
    for entry in data:
        if not isinstance(entry, dict):
            continue
        settings = entry.get("buildSettings")
        if not isinstance(settings, dict):
            continue
        name = entry.get("target") or entry.get("targetName") or settings.get("TARGET_NAME") or settings.get("PRODUCT_NAME") or "xcodebuild target"
        targets.append(target_from_settings(str(name), {str(k): str(v) for k, v in settings.items()}, ["xcodebuild -showBuildSettings -json"]))
    return targets


def parse_show_build_settings_text(raw: str) -> list[TargetSummary]:
    targets: list[TargetSummary] = []
    current_name: str | None = None
    current_settings: dict[str, str] = {}
    for line in raw.splitlines():
        header = re.match(r"Build settings for action .+ and target (.+):", line.strip())
        if header:
            if current_name and current_settings:
                targets.append(target_from_settings(current_name, current_settings, ["xcodebuild -showBuildSettings"]))
            current_name = header.group(1)
            current_settings = {}
            continue
        match = re.match(r"\s*([A-Z0-9_]+)\s*=\s*(.+?)\s*$", line)
        if match and current_name:
            current_settings[match.group(1)] = match.group(2)
    if current_name and current_settings:
        targets.append(target_from_settings(current_name, current_settings, ["xcodebuild -showBuildSettings"]))
    return targets


def find_xcode_container(root: Path, project: str | None, workspace: str | None) -> list[str]:
    if workspace:
        return ["-workspace", workspace]
    if project:
        return ["-project", project]
    workspaces = sorted(root.glob("*.xcworkspace"))
    if workspaces:
        return ["-workspace", str(workspaces[0])]
    projects = sorted(root.glob("*.xcodeproj"))
    if projects:
        return ["-project", str(projects[0])]
    return []


def run_xcodebuild(args: list[str], root: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["xcodebuild", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def discover_xcodebuild_targets(
    root: Path,
    project: str | None,
    workspace: str | None,
    scheme: str | None,
    notes: list[str],
) -> list[TargetSummary]:
    container_args = find_xcode_container(root, project, workspace)
    if not container_args:
        notes.append("xcodebuild discovery skipped: no .xcodeproj or .xcworkspace found.")
        return []
    try:
        list_result = run_xcodebuild([*container_args, "-list", "-json"], root)
    except (OSError, subprocess.TimeoutExpired) as error:
        notes.append(f"xcodebuild discovery failed: {error}")
        return []
    if list_result.returncode != 0:
        notes.append(f"xcodebuild -list failed: {list_result.stderr.strip()[:300]}")
        return []
    try:
        schemes, plain_targets = parse_xcodebuild_list_json(list_result.stdout)
    except Exception as error:
        notes.append(f"xcodebuild -list JSON parse failed: {error}")
        schemes, plain_targets = [], []

    selected_schemes = [scheme] if scheme else schemes[:8]
    targets: list[TargetSummary] = []
    for selected_scheme in selected_schemes:
        show_args = [*container_args, "-scheme", selected_scheme, "-showBuildSettings", "-json"]
        show_result = run_xcodebuild(show_args, root)
        parsed: list[TargetSummary] = []
        if show_result.returncode == 0:
            try:
                parsed = parse_show_build_settings_json(show_result.stdout)
            except Exception:
                parsed = []
        if not parsed:
            fallback = run_xcodebuild([*container_args, "-scheme", selected_scheme, "-showBuildSettings"], root)
            if fallback.returncode == 0:
                parsed = parse_show_build_settings_text(fallback.stdout)
        for target in parsed:
            target.evidence.append(f"xcodebuild scheme: {selected_scheme}")
        targets.extend(parsed)

    if not targets and plain_targets:
        notes.append("xcodebuild listed targets but build settings were unavailable; static target inference will be used.")
    return targets


def parse_pbx_settings(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for key in (
        "PRODUCT_BUNDLE_IDENTIFIER",
        "PRODUCT_NAME",
        "PRODUCT_TYPE",
        "SDKROOT",
        "SUPPORTED_PLATFORMS",
        "TARGETED_DEVICE_FAMILY",
        "SUPPORTS_MACCATALYST",
        "ENABLE_HARDENED_RUNTIME",
    ):
        match = re.search(rf"\b{key}\s*=\s*([^;\n]+)", text)
        if match:
            settings[key] = match.group(1).strip().strip('"')
    return settings


def pbx_unquote(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value.replace('\\"', '"')


def parse_pbx_objects(text: str) -> dict[str, tuple[str, str]]:
    objects: dict[str, tuple[str, str]] = {}
    index = 0
    pattern = re.compile(r"(?m)^\s*([A-F0-9]{24}) /\* ([^*]+) \*/ = \{")
    while True:
        match = pattern.search(text, index)
        if not match:
            break
        start = match.end()
        depth = 1
        position = start
        while position < len(text) and depth:
            char = text[position]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            position += 1
        body = text[start : position - 1]
        objects[match.group(1)] = (match.group(2), body)
        index = position
    return objects


def parse_pbx_list(body: str, key: str) -> list[str]:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*\((.*?)\);", body, re.DOTALL)
    if not match:
        return []
    return re.findall(r"\b([A-F0-9]{24})\b", match.group(1))


def parse_pbx_scalar(body: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*([^;\n]+);", body)
    if not match:
        return None
    return pbx_unquote(match.group(1))


def resolve_file_ref_path(file_id: str, objects: dict[str, tuple[str, str]], cache: dict[str, str]) -> str | None:
    if file_id in cache:
        return cache[file_id]
    item = objects.get(file_id)
    if not item:
        return None
    name, body = item
    isa = parse_pbx_scalar(body, "isa")
    if isa not in {"PBXFileReference", "PBXVariantGroup", "PBXGroup"}:
        return None
    path = parse_pbx_scalar(body, "path") or parse_pbx_scalar(body, "name") or name
    if not path:
        return None
    cache[file_id] = path
    return path


def normalize_member_path(path: str, all_files_by_name: dict[str, list[Path]], root: Path) -> str | None:
    clean = path.strip().strip('"')
    if not clean:
        return None
    clean = clean.replace("$(SRCROOT)/", "").replace("${SRCROOT}/", "").replace("$(PROJECT_DIR)/", "").replace("${PROJECT_DIR}/", "")
    candidate = (root / clean).resolve()
    if candidate.exists() and candidate.is_file():
        return rel(candidate, root)
    by_name = all_files_by_name.get(Path(clean).name, [])
    if len(by_name) == 1:
        return rel(by_name[0], root)
    suffix_matches = [path for path in by_name if str(path).endswith(clean)]
    if len(suffix_matches) == 1:
        return rel(suffix_matches[0], root)
    return clean


def load_xml_pbx_objects(project_file: Path) -> dict[str, Any] | None:
    try:
        with project_file.open("rb") as handle:
            data = plistlib.load(handle)
    except Exception:
        return None
    objects = data.get("objects") if isinstance(data, dict) else None
    return objects if isinstance(objects, dict) else None


def resolve_xml_file_ref_path(file_id: str, objects: dict[str, Any], cache: dict[str, str]) -> str | None:
    if file_id in cache:
        return cache[file_id]
    item = objects.get(file_id)
    if not isinstance(item, dict):
        return None
    if item.get("isa") not in {"PBXFileReference", "PBXVariantGroup", "PBXGroup"}:
        return None
    path = item.get("path") or item.get("name")
    if not isinstance(path, str):
        return None
    cache[file_id] = path
    return path


def parse_xml_pbx_target_memberships(root: Path, project_file: Path, objects: dict[str, Any], files: list[Path]) -> list[TargetMembership]:
    all_files_by_name: dict[str, list[Path]] = {}
    for path in files:
        all_files_by_name.setdefault(path.name, []).append(path)

    file_ref_cache: dict[str, str] = {}
    build_file_to_path: dict[str, str] = {}
    for object_id, item in objects.items():
        if not isinstance(item, dict) or item.get("isa") != "PBXBuildFile":
            continue
        file_ref = item.get("fileRef")
        if not isinstance(file_ref, str):
            continue
        raw_path = resolve_xml_file_ref_path(file_ref, objects, file_ref_cache)
        if not raw_path:
            continue
        normalized = normalize_member_path(raw_path, all_files_by_name, root)
        if normalized:
            build_file_to_path[object_id] = normalized

    memberships: list[TargetMembership] = []
    for item in objects.values():
        if not isinstance(item, dict) or item.get("isa") != "PBXNativeTarget":
            continue
        target_name = str(item.get("name") or item.get("productName") or "UnnamedTarget")
        member_files: set[str] = set()
        phase_names: list[str] = []
        for phase_id in item.get("buildPhases", []):
            phase = objects.get(phase_id)
            if not isinstance(phase, dict):
                continue
            phase_isa = phase.get("isa")
            if phase_isa not in {"PBXSourcesBuildPhase", "PBXResourcesBuildPhase", "PBXFrameworksBuildPhase", "PBXCopyFilesBuildPhase"}:
                continue
            phase_names.append(str(phase_isa))
            for build_file_id in phase.get("files", []):
                path = build_file_to_path.get(build_file_id)
                if path:
                    member_files.add(path)
        memberships.append(
            TargetMembership(
                target=target_name,
                product_type=item.get("productType") if isinstance(item.get("productType"), str) else None,
                file_count=len(member_files),
                files=sorted(member_files),
                evidence=[f"{rel(project_file, root)}: {', '.join(sorted(set(phase_names))) or 'no build phases'}"],
            )
        )
    return memberships


def parse_pbx_target_memberships(root: Path, files: list[Path]) -> list[TargetMembership]:
    all_files_by_name: dict[str, list[Path]] = {}
    for path in files:
        all_files_by_name.setdefault(path.name, []).append(path)

    memberships: list[TargetMembership] = []
    for project_file in [path for path in files if path.name == "project.pbxproj"]:
        xml_objects = load_xml_pbx_objects(project_file)
        if xml_objects:
            memberships.extend(parse_xml_pbx_target_memberships(root, project_file, xml_objects, files))
            continue
        text = read_text(project_file)
        objects = parse_pbx_objects(text)
        file_ref_cache: dict[str, str] = {}
        build_file_to_path: dict[str, str] = {}
        for object_id, (object_name, body) in objects.items():
            if parse_pbx_scalar(body, "isa") != "PBXBuildFile":
                continue
            file_ref = parse_pbx_scalar(body, "fileRef")
            if not file_ref:
                continue
            raw_path = resolve_file_ref_path(file_ref, objects, file_ref_cache) or object_name
            normalized = normalize_member_path(raw_path, all_files_by_name, root)
            if normalized:
                build_file_to_path[object_id] = normalized

        for _, (target_name, body) in objects.items():
            if parse_pbx_scalar(body, "isa") != "PBXNativeTarget":
                continue
            build_phase_ids = parse_pbx_list(body, "buildPhases")
            member_files: set[str] = set()
            phase_names: list[str] = []
            for phase_id in build_phase_ids:
                phase = objects.get(phase_id)
                if not phase:
                    continue
                phase_name, phase_body = phase
                phase_isa = parse_pbx_scalar(phase_body, "isa")
                if phase_isa not in {"PBXSourcesBuildPhase", "PBXResourcesBuildPhase", "PBXFrameworksBuildPhase", "PBXCopyFilesBuildPhase"}:
                    continue
                phase_names.append(phase_isa)
                for build_file_id in parse_pbx_list(phase_body, "files"):
                    path = build_file_to_path.get(build_file_id)
                    if path:
                        member_files.add(path)
            memberships.append(
                TargetMembership(
                    target=target_name,
                    product_type=parse_pbx_scalar(body, "productType"),
                    file_count=len(member_files),
                    files=sorted(member_files),
                    evidence=[f"{rel(project_file, root)}: {', '.join(sorted(set(phase_names))) or 'no build phases'}"],
                )
            )
    return memberships


def select_target_membership(
    memberships: list[TargetMembership],
    submitted_target: str | None,
    notes: list[str],
) -> TargetMembership | None:
    usable = [membership for membership in memberships if membership.file_count > 0]
    if submitted_target:
        for membership in usable:
            if membership.target == submitted_target:
                return membership
        lowered = submitted_target.lower()
        fuzzy = [membership for membership in usable if lowered in membership.target.lower()]
        if len(fuzzy) == 1:
            return fuzzy[0]
        notes.append(f"Target membership not scoped: submitted target `{submitted_target}` was not uniquely found.")
        return None
    app_memberships = [
        membership
        for membership in usable
        if membership.product_type in APP_PRODUCT_TYPES
    ]
    if len(app_memberships) == 1:
        notes.append(f"Automatically scoped file scan to sole app target `{app_memberships[0].target}`.")
        return app_memberships[0]
    if len(usable) == 1:
        notes.append(f"Automatically scoped file scan to sole target `{usable[0].target}`.")
        return usable[0]
    if usable:
        notes.append("Target membership discovered but not scoped; pass `--submitted-target <target>` to reduce cross-target noise.")
    return None


def scoped_text_files(
    text_files: list[Path],
    root: Path,
    membership: TargetMembership | None,
) -> list[Path]:
    if membership is None:
        return text_files
    member_paths = set(membership.files)
    always_include_suffixes = {".plist", ".entitlements", ".xcent", ".xcprivacy", ".xcconfig"}
    always_include_names = {"project.pbxproj", "Package.swift"}
    scoped: list[Path] = []
    for path in text_files:
        relative = rel(path, root)
        if relative in member_paths or path.suffix in always_include_suffixes or path.name in always_include_names:
            scoped.append(path)
    return scoped


def discover_xml_static_targets(root: Path, project_file: Path, objects: dict[str, Any]) -> list[TargetSummary]:
    targets: list[TargetSummary] = []
    for item in objects.values():
        if not isinstance(item, dict) or item.get("isa") != "PBXNativeTarget":
            continue
        settings: dict[str, str] = {}
        config_list_id = item.get("buildConfigurationList")
        config_list = objects.get(config_list_id) if isinstance(config_list_id, str) else None
        config_ids = config_list.get("buildConfigurations", []) if isinstance(config_list, dict) else []
        for config_id in config_ids:
            config = objects.get(config_id)
            if not isinstance(config, dict):
                continue
            build_settings = config.get("buildSettings")
            if not isinstance(build_settings, dict):
                continue
            for key in (
                "PRODUCT_BUNDLE_IDENTIFIER",
                "PRODUCT_NAME",
                "PRODUCT_TYPE",
                "SDKROOT",
                "SUPPORTED_PLATFORMS",
                "TARGETED_DEVICE_FAMILY",
                "SUPPORTS_MACCATALYST",
                "ENABLE_HARDENED_RUNTIME",
            ):
                value = build_settings.get(key)
                if value is not None and key not in settings:
                    settings[key] = str(value)
        if item.get("productType") and "PRODUCT_TYPE" not in settings:
            settings["PRODUCT_TYPE"] = str(item["productType"])
        name = str(item.get("name") or item.get("productName") or settings.get("PRODUCT_NAME") or "Xcode target")
        if settings:
            targets.append(target_from_settings(name, settings, [f"{rel(project_file, root)}: target build settings"]))
    return targets


def discover_static_targets(root: Path, files: list[Path], parsed_plists: list[tuple[Path, Any]]) -> list[TargetSummary]:
    targets: list[TargetSummary] = []
    for path in files:
        if path.name != "project.pbxproj":
            continue
        xml_objects = load_xml_pbx_objects(path)
        if xml_objects:
            targets.extend(discover_xml_static_targets(root, path, xml_objects))
            continue
        settings = parse_pbx_settings(read_text(path))
        if settings:
            name = settings.get("PRODUCT_NAME") or path.parent.stem or "Static project settings"
            targets.append(target_from_settings(name, settings, [f"{rel(path, root)}: build settings"]))
    for path, data in parsed_plists:
        if path.name != "Info.plist" or not isinstance(data, dict):
            continue
        settings: dict[str, str] = {}
        if data.get("CFBundleIdentifier"):
            settings["PRODUCT_BUNDLE_IDENTIFIER"] = str(data["CFBundleIdentifier"])
        if data.get("CFBundleName"):
            settings["PRODUCT_NAME"] = str(data["CFBundleName"])
        if data.get("CFBundlePackageType"):
            settings["PRODUCT_TYPE"] = str(data["CFBundlePackageType"])
        device_families = data.get("UIDeviceFamily")
        if isinstance(device_families, int):
            settings["TARGETED_DEVICE_FAMILY"] = str(device_families)
        elif isinstance(device_families, list):
            settings["TARGETED_DEVICE_FAMILY"] = ",".join(str(item) for item in device_families)
        if settings:
            identity_values = [settings.get("PRODUCT_NAME"), settings.get("PRODUCT_BUNDLE_IDENTIFIER")]
            identity_is_unresolved = identity_values and all(
                value is None or has_build_setting_reference(value)
                for value in identity_values
            )
            if targets and identity_is_unresolved:
                continue
            targets.append(target_from_settings(settings.get("PRODUCT_NAME", rel(path, root)), settings, [f"{rel(path, root)}: Info.plist"]))
    return targets


def detect_target_platforms(
    root: Path,
    files: list[Path],
    parsed_plists: list[tuple[Path, Any]],
    targets: list[TargetSummary],
) -> list[TargetPlatform]:
    signals: dict[str, list[str]] = {platform: [] for platform in PLATFORM_FOCUS}
    strong_platforms: set[str] = set()

    def add_signal(platform: str, evidence: str, strong: bool = False) -> None:
        if platform not in signals:
            return
        if evidence not in signals[platform] and len(signals[platform]) < 10:
            signals[platform].append(evidence)
        if strong:
            strong_platforms.add(platform)

    for target in targets:
        for platform in target.platforms:
            add_signal(platform, f"{target.name}: {', '.join(target.evidence)}", strong=True)

    for path, data in parsed_plists:
        if not isinstance(data, dict):
            continue
        device_families = data.get("UIDeviceFamily")
        if isinstance(device_families, int):
            device_families = [device_families]
        if isinstance(device_families, list):
            for family in device_families:
                platform = DEVICE_FAMILY_PLATFORMS.get(str(family))
                if platform:
                    add_signal(platform, f"{rel(path, root)}:UIDeviceFamily contains {family}", strong=True)
        if data.get("WKWatchKitApp"):
            add_signal("watchOS", f"{rel(path, root)}:WKWatchKitApp", strong=True)

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
                        add_signal(platform, f"{rel(path, root)}:{line_number}: {stripped[:140]}", strong=strong)
                        break

    target_platforms: list[TargetPlatform] = []
    for platform in PLATFORM_FOCUS:
        evidence = signals[platform]
        if not evidence:
            continue
        confidence = "high" if platform in strong_platforms else "medium"
        target_platforms.append(
            TargetPlatform(
                platform=platform,
                confidence=confidence,
                evidence=evidence,
                guideline_focus=PLATFORM_FOCUS[platform],
            )
        )
    return target_platforms


def declared_required_reason_categories(privacy_manifests: list[tuple[Path, Any]]) -> set[str]:
    declared: set[str] = set()
    for _, data in privacy_manifests:
        if not isinstance(data, dict):
            continue
        entries = data.get("NSPrivacyAccessedAPITypes")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("NSPrivacyAccessedAPIType"), str):
                declared.add(entry["NSPrivacyAccessedAPIType"])
    return declared


def validate_privacy_manifests(
    root: Path,
    privacy_manifest_paths: list[Path],
    privacy_manifests: list[tuple[Path, Any]],
    invalid_plists: list[tuple[Path, str]],
    text_files: list[Path],
    findings: list[Finding],
) -> None:
    for path, error in invalid_plists:
        if path.name == "PrivacyInfo.xcprivacy":
            add(
                findings,
                "HIGH",
                "Privacy",
                "Invalid PrivacyInfo.xcprivacy file",
                "high",
                [f"{rel(path, root)}: {error}"],
                "Fix the privacy manifest plist syntax before submission; invalid manifests can fail App Store Connect processing.",
                "privacy-invalid-privacy-manifest",
            )

    for path, data in privacy_manifests:
        if not isinstance(data, dict):
            add(
                findings,
                "HIGH",
                "Privacy",
                "PrivacyInfo.xcprivacy is not a dictionary",
                "high",
                [rel(path, root)],
                "Replace the privacy manifest with a valid dictionary containing Apple's expected privacy keys.",
                "privacy-manifest-not-dictionary",
            )
            continue
        if not data:
            add(
                findings,
                "MEDIUM",
                "Privacy",
                "Empty PrivacyInfo.xcprivacy file",
                "medium",
                [rel(path, root)],
                "Populate the privacy manifest with accurate collected data, tracking, and required-reason API declarations, or verify an empty manifest is correct.",
                "privacy-empty-privacy-manifest",
            )
        accessed_api_types = data.get("NSPrivacyAccessedAPITypes")
        if accessed_api_types is not None and not isinstance(accessed_api_types, list):
            add(
                findings,
                "HIGH",
                "Privacy",
                "Invalid NSPrivacyAccessedAPITypes value",
                "high",
                [f"{rel(path, root)}: NSPrivacyAccessedAPITypes must be an array"],
                "Use an array of dictionaries with NSPrivacyAccessedAPIType and NSPrivacyAccessedAPITypeReasons.",
                "privacy-invalid-accessed-api-types",
            )
        elif isinstance(accessed_api_types, list):
            for index, entry in enumerate(accessed_api_types):
                if not isinstance(entry, dict):
                    add(
                        findings,
                        "HIGH",
                        "Privacy",
                        "Invalid required-reason API declaration",
                        "high",
                        [f"{rel(path, root)}: NSPrivacyAccessedAPITypes[{index}] is not a dictionary"],
                        "Use a dictionary entry with NSPrivacyAccessedAPIType and NSPrivacyAccessedAPITypeReasons.",
                        f"privacy-invalid-accessed-api-entry-{index}",
                    )
                    continue
                reasons = entry.get("NSPrivacyAccessedAPITypeReasons")
                if not entry.get("NSPrivacyAccessedAPIType") or not isinstance(reasons, list) or not reasons:
                    add(
                        findings,
                        "HIGH",
                        "Privacy",
                        "Incomplete required-reason API declaration",
                        "high",
                        [f"{rel(path, root)}: NSPrivacyAccessedAPITypes[{index}]={entry!r}"],
                        "Add the API category and at least one approved reason code for each required-reason API declaration.",
                        f"privacy-incomplete-accessed-api-entry-{index}",
                    )
        if data.get("NSPrivacyTracking") is True and not data.get("NSPrivacyTrackingDomains"):
            add(
                findings,
                "MEDIUM",
                "Privacy",
                "Tracking declared without tracking domains",
                "medium",
                [f"{rel(path, root)}: NSPrivacyTracking=true"],
                "Verify tracking domains are declared where applicable and App Privacy answers match tracking behavior.",
                "privacy-tracking-without-domains",
            )

    declared_categories = declared_required_reason_categories(privacy_manifests)
    for category_key, (label, patterns) in REQUIRED_REASON_CLUES.items():
        hits = text_hits(text_files, patterns, root, max_hits=4)
        if hits and category_key not in declared_categories:
            evidence = [f"{label}: {hit}" for hit in hits]
            manifest_note = "No PrivacyInfo.xcprivacy found." if not privacy_manifest_paths else f"Declared categories: {sorted(declared_categories)}"
            add(
                findings,
                "MEDIUM",
                "Privacy",
                f"Potential required-reason API use not declared: {label}",
                "medium",
                [manifest_note, *evidence],
                f"Inspect these APIs against Apple's required-reason API categories and add {category_key} with approved reason codes when applicable.",
                f"privacy-missing-required-reason-{slugify(label)}",
            )

    collection_hits = text_hits(text_files, PRIVACY_COLLECTION_CLUES, root, max_hits=5)
    declares_collected_data = any(isinstance(data, dict) and "NSPrivacyCollectedDataTypes" in data for _, data in privacy_manifests)
    if collection_hits and privacy_manifests and not declares_collected_data:
        add(
            findings,
            "LOW",
            "Privacy",
            "Data collection clues without NSPrivacyCollectedDataTypes",
            "low",
            collection_hits,
            "Verify whether the app or SDKs collect data and align PrivacyInfo.xcprivacy plus App Privacy answers with actual behavior.",
            "privacy-collection-clues-without-collected-data-types",
        )


def load_suppressions(root: Path) -> dict[str, str]:
    candidates = [
        root / ".appstore-review-risk.json",
        root / ".appstore-review-risk.yml",
        root / ".appstore-review-risk.yaml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        text = read_text(path)
        if path.suffix == ".json":
            data = json.loads(text)
            entries = data.get("suppressions", [])
            return {
                str(entry.get("id")): str(entry.get("reason", "No reason provided."))
                for entry in entries
                if isinstance(entry, dict) and entry.get("id")
            }
        suppressions: dict[str, str] = {}
        current_id: str | None = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            id_match = re.match(r"-\s*id:\s*[\"']?([^\"']+?)[\"']?\s*$", line)
            if id_match:
                current_id = id_match.group(1).strip()
                suppressions[current_id] = "No reason provided."
                continue
            reason_match = re.match(r"reason:\s*[\"']?(.+?)[\"']?\s*$", line)
            if current_id and reason_match:
                suppressions[current_id] = reason_match.group(1).strip()
        return suppressions
    return {}


def apply_suppressions(findings: list[Finding], suppressions: dict[str, str]) -> tuple[list[Finding], list[Suppression]]:
    if not suppressions:
        return findings, []
    kept: list[Finding] = []
    applied: list[Suppression] = []
    for finding in findings:
        reason = suppressions.get(finding.id)
        if reason:
            applied.append(Suppression(finding_id=finding.id, reason=reason))
        else:
            kept.append(finding)
    return kept, applied


def artifact_evidence(files: list[Path], root: Path, patterns: list[str]) -> list[str]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    evidence: list[str] = []
    for path in files:
        candidate = rel(path, root)
        if any(pattern.search(candidate) for pattern in compiled):
            evidence.append(candidate)
            if len(evidence) >= 5:
                break
    return evidence


def build_artifact_checks(root: Path, files: list[Path], findings: list[Finding]) -> list[ArtifactCheck]:
    checks: list[ArtifactCheck] = []
    for name, patterns in ARTIFACT_PATTERNS.items():
        evidence = artifact_evidence(files, root, patterns)
        checks.append(
            ArtifactCheck(
                name=name,
                status="present_in_repo" if evidence else "missing_from_repo",
                evidence=evidence or ["No matching artifact discovered in repository."],
                recommendation=f"Provide or verify {name.lower()} before review; many rejection risks live outside source code.",
            )
        )

    finding_categories = {finding.category for finding in findings}
    finding_titles = " ".join(finding.title for finding in findings).lower()
    conditional_checks = [
        ("In-app purchase/subscription product configuration", "StoreKit" in finding_categories, [r"\.storekit$", r"subscription", r"in.?app.?purchase", r"products\.json"]),
        ("Entitlement approval records", "Entitlements" in finding_categories, [r"entitlement", r"approval", r"capabilit"]),
        ("Account deletion proof", "account deletion" in finding_titles, [r"delete.?account", r"account.?deletion"]),
        ("UGC moderation policy", "User-generated content" in finding_categories, [r"moderation", r"abuse", r"report", r"block"]),
    ]
    for name, needed, patterns in conditional_checks:
        if not needed:
            continue
        evidence = artifact_evidence(files, root, patterns)
        checks.append(
            ArtifactCheck(
                name=name,
                status="present_in_repo" if evidence else "needed_if_applicable",
                evidence=evidence or ["No matching artifact discovered in repository."],
                recommendation=f"Confirm {name.lower()} is available in App Store Connect review notes or repository artifacts.",
            )
        )
    return checks


def scan_result(
    root: Path,
    *,
    use_xcodebuild: bool = False,
    project: str | None = None,
    workspace: str | None = None,
    scheme: str | None = None,
    submitted_target: str | None = None,
) -> ScanResult:
    files = list(iter_files(root))
    text_files = [path for path in files if path.suffix in TEXT_EXTENSIONS]
    plist_files = [path for path in files if path.suffix in {".plist", ".entitlements", ".xcprivacy", ".xcent"}]
    loaded_plists = [(path, *load_plist(path)) for path in plist_files]
    parsed_plists = [(path, data) for path, data, error in loaded_plists if error is None]
    invalid_plists = [(path, error or "unknown plist error") for path, data, error in loaded_plists if error is not None]
    info_plists = [
        (path, data)
        for path, data in parsed_plists
        if path.name == "Info.plist" or (isinstance(data, dict) and any(str(key).startswith("NS") for key in data))
    ]
    privacy_manifest_paths = [path for path in plist_files if path.name == "PrivacyInfo.xcprivacy"]
    privacy_manifests = [(path, data) for path, data in parsed_plists if path.name == "PrivacyInfo.xcprivacy"]
    entitlement_plists = [(path, data) for path, data in parsed_plists if path.suffix in {".entitlements", ".xcent"}]
    findings: list[Finding] = []
    notes: list[str] = []

    target_memberships = parse_pbx_target_memberships(root, files)
    selected_membership = select_target_membership(target_memberships, submitted_target, notes)
    scan_text_files = scoped_text_files(text_files, root, selected_membership)

    targets = discover_static_targets(root, files, parsed_plists)
    if use_xcodebuild:
        xcodebuild_targets = discover_xcodebuild_targets(root, project, workspace, scheme, notes)
        if xcodebuild_targets:
            targets = xcodebuild_targets

    target_platforms = detect_target_platforms(root, files, parsed_plists, targets)

    has_xcode_artifact = any(path.name == "project.pbxproj" or path.suffix == ".swift" for path in files)
    if has_xcode_artifact and not privacy_manifest_paths:
        add(
            findings,
            "MEDIUM",
            "Privacy",
            "No PrivacyInfo.xcprivacy file found",
            "medium",
            ["No PrivacyInfo.xcprivacy discovered in the scanned tree."],
            "Verify whether the app or bundled SDKs collect data or use required-reason APIs. Add valid privacy manifests where required and align App Privacy answers.",
            "privacy-no-privacy-manifest",
        )

    validate_privacy_manifests(root, privacy_manifest_paths, privacy_manifests, invalid_plists, scan_text_files, findings)

    for usage_key, patterns in PERMISSION_CLUES.items():
        hits = text_hits(scan_text_files, patterns, root, max_hits=4)
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
                f"permissions-missing-{slugify(key_label)}",
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
                    f"permissions-vague-{slugify(usage_key)}",
                )

    att_hits = text_hits(scan_text_files, [r"\bATTrackingManager\b", r"\bAppTrackingTransparency\b", r"\bASIdentifierManager\b", r"\badvertisingIdentifier\b"], root)
    if att_hits and not plist_has_key(info_plists, "NSUserTrackingUsageDescription"):
        add(
            findings,
            "HIGH",
            "Tracking",
            "Tracking or IDFA APIs found without NSUserTrackingUsageDescription",
            "medium",
            att_hits,
            "Add a clear tracking usage description, verify ATT prompt timing, and align App Privacy answers with actual tracking behavior.",
            "tracking-missing-nsusertrackingusagedescription",
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
                    f"entitlements-{slugify(key)}",
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
                f"storekit-{slugify(key)}",
            )

    external_purchase_hits = text_hits(scan_text_files, EXTERNAL_PURCHASE_PATTERNS, root)
    if external_purchase_hits:
        add(
            findings,
            "HIGH",
            "StoreKit",
            "External purchase or web billing language found",
            "medium",
            external_purchase_hits,
            "Confirm the app is not steering digital purchases outside StoreKit unless it has the correct entitlement, storefront eligibility, disclosure flow, and review notes.",
            "storekit-external-purchase-language",
        )

    storekit_hits = text_hits(scan_text_files, STOREKIT_PATTERNS, root, max_hits=5)
    if storekit_hits and not all_text_has(scan_text_files, RESTORE_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "StoreKit",
            "StoreKit usage found without obvious restore/current entitlement path",
            "low",
            storekit_hits,
            "Verify the UI exposes purchase restoration or current entitlement recovery where appropriate, and include subscription review notes.",
            "storekit-missing-restore-path",
        )

    social_hits = text_hits(scan_text_files, SOCIAL_LOGIN_PATTERNS, root)
    if social_hits and not all_text_has(scan_text_files, APPLE_SIGN_IN_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "Authentication",
            "Third-party/social login found without obvious Sign in with Apple",
            "medium",
            social_hits,
            "Verify whether Sign in with Apple parity is required for the login options offered, or document the applicable exception.",
            "authentication-third-party-login-without-apple",
        )

    account_hits = text_hits(scan_text_files, ACCOUNT_PATTERNS, root, max_hits=6)
    if account_hits and not all_text_has(scan_text_files, DELETE_ACCOUNT_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "Accounts",
            "Account creation/login clues found without obvious account deletion flow",
            "medium",
            account_hits,
            "Verify the app exposes an in-app account deletion path or a clearly compliant deletion flow, and document it in review notes if not obvious.",
            "accounts-missing-account-deletion-flow",
        )

    ugc_hits = text_hits(scan_text_files, UGC_PATTERNS, root, max_hits=6)
    if ugc_hits and not all_text_has(scan_text_files, MODERATION_PATTERNS, root):
        add(
            findings,
            "MEDIUM",
            "User-generated content",
            "UGC/social clues found without obvious reporting or blocking flow",
            "low",
            ugc_hits,
            "Inspect the actual product behavior for moderation, reporting, blocking, abuse handling, filtering, and reviewer-accessible test content.",
            "ugc-missing-reporting-blocking-flow",
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
            "background-ui-background-modes-enabled",
        )

    private_hits = text_hits(scan_text_files, PRIVATE_API_PATTERNS, root)
    if private_hits:
        add(
            findings,
            "HIGH",
            "Private APIs",
            "Potential private API or dynamic private selector usage",
            "low",
            private_hits,
            "Inspect these calls carefully. Remove private API usage or prove the dynamic selector is public and necessary.",
            "private-api-dynamic-private-selector",
        )

    placeholder_hits = text_hits(scan_text_files, PLACEHOLDER_PATTERNS, root, max_hits=10, exclude_patterns=PLACEHOLDER_EXCLUDE_PATTERNS)
    if placeholder_hits:
        add(
            findings,
            "LOW",
            "App completeness",
            "Placeholder, local, or unfinished text found",
            "low",
            placeholder_hits,
            "Review whether these strings can appear in the submitted app, metadata, URLs, or review-visible flows. Remove unfinished content before submission.",
            "app-completeness-placeholder-content",
        )

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda finding: (severity_order.get(finding.severity, 9), finding.category, finding.title))
    findings, suppressions_applied = apply_suppressions(findings, load_suppressions(root))
    artifact_checks = build_artifact_checks(root, files, findings)
    return ScanResult(
        target_platforms=target_platforms,
        targets=targets,
        target_memberships=target_memberships,
        scoped_target=selected_membership.target if selected_membership else None,
        findings=findings,
        artifact_checks=artifact_checks,
        suppressions_applied=suppressions_applied,
        notes=notes,
    )


def scan(root: Path) -> list[Finding]:
    return scan_result(root).findings


def print_markdown(root: Path, result: ScanResult) -> None:
    print("# Apple App Review Risk Scan")
    print()
    print(f"Target: `{root}`")
    print()
    print("Static heuristic results. Inspect every finding manually before treating it as an App Review issue.")
    print()
    if result.targets:
        print("## Target Matrix")
        print()
        print("| Target | Bundle ID | Product Type | Platforms | Submission Path | Evidence |")
        print("| --- | --- | --- | --- | --- | --- |")
        for target in result.targets:
            print(
                f"| {target.name} | {target.bundle_identifier or 'unknown'} | {target.product_type or 'unknown'} | "
                f"{', '.join(target.platforms) or 'unknown'} | {target.submission_path} | {'; '.join(target.evidence)} |"
            )
        print()
    if result.scoped_target:
        print(f"Scoped file scan: `{result.scoped_target}`")
        print()
    elif result.target_memberships:
        print("Target memberships discovered; pass `--submitted-target <target>` to scope code-pattern findings.")
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

    if result.notes:
        print("## Scanner Notes")
        print()
        for note in result.notes:
            print(f"- {note}")
        print()

    findings = result.findings
    if findings:
        print("## Findings")
        print()
        print("| Severity | Category | ID | Title | Confidence |")
        print("| --- | --- | --- | --- | --- |")
        for finding in findings:
            print(f"| {finding.severity} | {finding.category} | `{finding.id}` | {finding.title} | {finding.confidence} |")
        print()
        for finding in findings:
            print(f"## [{finding.severity}] {finding.title}")
            print()
            print(f"- ID: `{finding.id}`")
            print(f"- Category: {finding.category}")
            print(f"- Confidence: {finding.confidence}")
            print("- Evidence:")
            for item in finding.evidence:
                print(f"  - `{item}`")
            print(f"- Recommendation: {finding.recommendation}")
            print()
    else:
        print("No obvious review-risk signals were found by the scanner.")
        print()

    if result.artifact_checks:
        print("## App Store Connect Artifact Checks")
        print()
        print("| Artifact | Status | Recommendation |")
        print("| --- | --- | --- |")
        for check in result.artifact_checks:
            print(f"| {check.name} | {check.status} | {check.recommendation} |")
        print()

    if result.suppressions_applied:
        print("## Suppressions Applied")
        print()
        for suppression in result.suppressions_applied:
            print(f"- `{suppression.finding_id}`: {suppression.reason}")
        print()


def truncate(value: str, limit: int = 140) -> str:
    normalized = re.sub(r"\s+", " ", value.strip())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def compact_result(root: Path, result: ScanResult, max_findings: int = 12) -> dict[str, Any]:
    max_findings = max(0, max_findings)
    severity_counts = Counter(finding.severity for finding in result.findings)
    platform_summary = [
        {
            "platform": target.platform,
            "confidence": target.confidence,
        }
        for target in result.target_platforms
    ]
    target_summary = [
        {
            "name": target.name,
            "bundle_identifier": target.bundle_identifier,
            "platforms": target.platforms,
            "submission_path": target.submission_path,
        }
        for target in result.targets[:8]
    ]
    membership_summary = [
        {
            "target": membership.target,
            "product_type": membership.product_type,
            "file_count": membership.file_count,
        }
        for membership in result.target_memberships[:12]
    ]
    findings = [
        {
            "severity": finding.severity,
            "id": finding.id,
            "category": finding.category,
            "title": finding.title,
            "confidence": finding.confidence,
            "first_evidence": finding.evidence[0] if finding.evidence else None,
        }
        for finding in result.findings[:max_findings]
    ]
    artifact_gaps = [
        {
            "name": check.name,
            "status": check.status,
        }
        for check in result.artifact_checks
        if check.status != "present_in_repo"
    ]
    return {
        "target": str(root),
        "platforms": platform_summary,
        "targets": target_summary,
        "target_memberships": membership_summary,
        "scoped_target": result.scoped_target,
        "finding_counts": dict(severity_counts),
        "findings_shown": findings,
        "findings_omitted": max(0, len(result.findings) - len(findings)),
        "artifact_gaps": artifact_gaps,
        "suppressions_applied": len(result.suppressions_applied),
        "notes": result.notes[:5],
    }


def print_compact(root: Path, result: ScanResult, max_findings: int = 12) -> None:
    summary = compact_result(root, result, max_findings=max_findings)
    print("# Apple App Review Risk Scan Summary")
    print()
    print(f"Target: `{root}`")
    platforms = summary["platforms"]
    if platforms:
        joined = ", ".join(f"{item['platform']} ({item['confidence']})" for item in platforms)
        print(f"Platforms: {joined}")
    else:
        print("Platforms: unknown")
    if summary["targets"]:
        print("Targets:")
        for target in summary["targets"]:
            platforms_text = ", ".join(target["platforms"]) or "unknown"
            print(f"- {target['name']}: {target['bundle_identifier'] or 'unknown'}, {platforms_text}, {target['submission_path']}")
    if summary["scoped_target"]:
        print(f"Scoped file scan: {summary['scoped_target']}")
    elif summary["target_memberships"]:
        names = ", ".join(f"{item['target']} ({item['file_count']})" for item in summary["target_memberships"])
        print(f"Target memberships: {names}")
    counts = summary["finding_counts"]
    count_text = ", ".join(f"{severity}={counts.get(severity, 0)}" for severity in ("HIGH", "MEDIUM", "LOW", "INFO"))
    print(f"Findings: {count_text}")
    print()
    for finding in summary["findings_shown"]:
        evidence = finding["first_evidence"] or "No evidence captured."
        print(f"- {finding['severity']} `{finding['id']}`: {finding['title']} ({finding['confidence']})")
        print(f"  evidence: `{truncate(evidence)}`")
    if summary["findings_omitted"]:
        print(f"- ... {summary['findings_omitted']} more finding(s) omitted; rerun with `--format markdown` or `--format json` for details.")
    if summary["artifact_gaps"]:
        print()
        print("Artifact gaps:")
        for gap in summary["artifact_gaps"]:
            print(f"- {gap['name']}: {gap['status']}")
    if summary["suppressions_applied"]:
        print()
        print(f"Suppressions applied: {summary['suppressions_applied']}")
    if summary["notes"]:
        print()
        print("Notes:")
        for note in summary["notes"]:
            print(f"- {truncate(note)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Scan Apple app repositories for App Review risk signals.")
    parser.add_argument("path", type=Path, help="Path to an Apple app repository or project directory.")
    parser.add_argument("--format", choices=("compact", "markdown", "json", "compact-json"), default="compact")
    parser.add_argument("--max-findings", type=int, default=12, help="Maximum findings to show in compact output.")
    parser.add_argument("--fail-on", choices=("none", "high", "medium"), default="none")
    parser.add_argument("--xcodebuild", action="store_true", help="Run xcodebuild -list/-showBuildSettings to extract exact target metadata.")
    parser.add_argument("--project", help="Specific .xcodeproj path to pass to xcodebuild.")
    parser.add_argument("--workspace", help="Specific .xcworkspace path to pass to xcodebuild.")
    parser.add_argument("--scheme", help="Specific scheme to inspect with xcodebuild.")
    parser.add_argument("--submitted-target", help="Xcode target name to use for target-aware file membership scoping.")
    args = parser.parse_args(argv)

    root = args.path.expanduser().resolve()
    if not root.exists():
        print(f"Path does not exist: {root}", file=sys.stderr)
        return 2

    result = scan_result(
        root,
        use_xcodebuild=args.xcodebuild,
        project=args.project,
        workspace=args.workspace,
        scheme=args.scheme,
        submitted_target=args.submitted_target,
    )
    if args.format == "json":
        print(json.dumps({"target": str(root), **asdict(result)}, indent=2))
    elif args.format == "compact-json":
        print(json.dumps(compact_result(root, result, max_findings=args.max_findings), indent=2))
    elif args.format == "compact":
        print_compact(root, result, max_findings=args.max_findings)
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
