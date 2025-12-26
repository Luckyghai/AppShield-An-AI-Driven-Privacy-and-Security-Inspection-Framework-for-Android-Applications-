from apkutils2 import APK

def inspect_apk(apk_path: str):
    apk = APK(apk_path)
    manifest = apk.get_manifest()

    print("=== APK INFO ===")
    # Package name
    pkg = manifest.get('@package')
    print("Package name:", pkg)

    # Permissions
    uses_perm = manifest.get('uses-permission', [])
    print("\nPermissions:")
    if not uses_perm:
        print("  (No explicit permissions or none parsed)")
    else:
        for perm in uses_perm:
            name = perm.get('@android:name', 'UNKNOWN')
            print("  -", name)

if __name__ == "__main__":
    apk_file = "example.apk"  # your test apk in this folder
    inspect_apk(apk_file)
