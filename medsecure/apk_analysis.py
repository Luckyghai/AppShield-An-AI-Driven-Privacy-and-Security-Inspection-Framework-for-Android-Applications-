# apk_analysis.py
from apkutils2 import APK

def analyze_apk(apk_path: str):
    """
    Returns a dictionary with basic APK info:
    - package name
    - permissions
    """
    apk = APK(apk_path)
    manifest = apk.get_manifest()

    pkg = manifest.get('@package')

    # extract permissions robustly
    permissions = []

    # Case 1: top-level 'uses-permission'
    if 'uses-permission' in manifest:
        data = manifest['uses-permission']
        if isinstance(data, dict):
            name = data.get('@android:name')
            if name:
                permissions.append(name)
        elif isinstance(data, list):
            for item in data:
                name = item.get('@android:name')
                if name:
                    permissions.append(name)

    # Case 2: nested under 'manifest' tag
    if 'manifest' in manifest and isinstance(manifest['manifest'], dict):
        inner = manifest['manifest']
        if 'uses-permission' in inner:
            data = inner['uses-permission']
            if isinstance(data, dict):
                name = data.get('@android:name')
                if name:
                    permissions.append(name)
            elif isinstance(data, list):
                for item in data:
                    name = item.get('@android:name')
                    if name:
                        permissions.append(name)

    # remove duplicates + sort
    permissions = sorted(set(permissions))

    return {
        "package_name": pkg,
        "permissions": permissions
    }

if __name__ == "__main__":
    info = analyze_apk("F-Droid.apk")  # make sure sample.apk exists in this folder
    print("Package:", info["package_name"])
    print("Permissions:")
    for p in info["permissions"]:
        print(" -", p)
