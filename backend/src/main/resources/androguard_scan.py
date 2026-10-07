"""Static APK/DEX inventory. The APK is parsed as data and never executed."""

import json
import sys
from pathlib import Path

from androguard.misc import AnalyzeAPK


def value(obj, method, default=None):
    function = getattr(obj, method, None)
    if function is None:
        return default
    try:
        return function()
    except Exception:
        return default


def text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).replace("\x00", "")[:512]


def attribute(obj, name, getter):
    raw = getattr(obj, name, None)
    return text(raw if raw is not None else value(obj, getter))


PATTERNS = (
    ("Ljava/lang/Runtime;", "exec", "Runtime.exec", "EXECUTION", "HIGH"),
    ("Ldalvik/system/DexClassLoader;", "<init>", "DexClassLoader", "DYNAMIC_LOADING", "HIGH"),
    ("Landroid/webkit/WebView;", "addJavascriptInterface", "WebView.addJavascriptInterface", "WEB", "MEDIUM"),
    ("Ljavax/crypto/Cipher;", "getInstance", "Cipher.getInstance", "CRYPTOGRAPHY", "MEDIUM"),
)


def analyze(apk_path):
    apk, dexes, application = AnalyzeAPK(apk_path)
    summary = value(application, "summary", {}) or {}
    manifest = getattr(apk, "axml", None)
    metadata = {
        "packageName": text(value(apk, "get_package") or summary.get("package") or getattr(manifest, "package", None)),
        "applicationName": text(value(apk, "get_app_name") or summary.get("app_name")),
        "versionName": text(value(apk, "get_androidversion_name")),
        "versionCode": text(value(apk, "get_androidversion_code")),
        "minSdk": text(value(apk, "get_min_sdk_version")),
        "targetSdk": text(value(apk, "get_target_sdk_version")),
    }
    permissions = sorted({text(item) for item in (value(apk, "get_permissions", []) or []) if item})[:1000]
    dex_names = sorted({text(item) for item in (value(apk, "get_dex_names", []) or []) if item})[:100]
    classes = set()
    method_count = 0
    findings = []
    seen = set()
    for dex in dexes:
        for cls in value(dex, "get_classes", []) or []:
            name = attribute(cls, "name", "get_name")
            if name:
                classes.add(name)
        for method in value(dex, "get_methods", []) or []:
            method_count += 1
            owner = attribute(method, "class_name", "get_class_name")
            name = attribute(method, "name", "get_name")
            if not owner or not name:
                continue
            for expected_owner, expected_name, api_name, category, severity in PATTERNS:
                normalized_owner = "L" + owner.replace(".", "/") + ";" if not owner.startswith("L") else owner
                if normalized_owner == expected_owner and name == expected_name and api_name not in seen:
                    seen.add(api_name)
                    findings.append({
                        "className": owner,
                        "methodName": name,
                        "apiName": api_name,
                        "category": category,
                        "severity": severity,
                        "description": "Androguard DEX method reference; presence does not prove invocation.",
                    })
    return {
        "metadata": metadata,
        "permissions": permissions,
        "apiFindings": findings,
        "dexFileNames": dex_names,
        "dexClassCount": len(classes),
        "dexMethodCount": method_count,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(2)
    result = analyze(sys.argv[1])
    Path(sys.argv[2]).write_text(json.dumps(result, ensure_ascii=True), encoding="utf-8")
