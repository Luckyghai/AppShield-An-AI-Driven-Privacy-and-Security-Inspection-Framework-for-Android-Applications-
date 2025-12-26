# nlp_risk.py
from typing import List, Dict
import logging

# small keyword fallback (kept similar to previous)
def _keyword_extract_claims(policy_text: str) -> Dict[str, bool]:
    text = policy_text.lower()
    return {
        "mentions_location": any(word in text for word in ["location", "geolocation", "gps", "locational data"]),
        "mentions_contacts": any(word in text for word in ["contacts", "address book", "contact list"]),
        "mentions_camera": any(word in text for word in ["camera", "photos", "take pictures", "video recording"]),
        "mentions_microphone": any(word in text for word in ["microphone", "audio recording", "voice recording"]),
        "mentions_storage": any(word in text for word in ["storage", "files on your device", "media files", "photos and videos"]),
        "mentions_phone": any(word in text for word in ["phone number", "call log", "telephony"]),
        "mentions_ads_tracking": any(word in text for word in ["advertising id", "ads", "ad partners", "personalized ads", "analytics partners"]),
        "mentions_third_parties": any(word in text for word in ["third parties", "partners", "service providers", "affiliates"]),
        "mentions_security": any(word in text for word in ["encrypt", "security", "protect your data", "secure", "safeguard"]),
    }

_ZS_CLASSIFIER = None
_ZS_MODEL_NAME = "facebook/bart-large-mnli"

def _init_zero_shot():
    global _ZS_CLASSIFIER
    if _ZS_CLASSIFIER is not None:
        return True
    try:
        from transformers import pipeline
        _ZS_CLASSIFIER = pipeline("zero-shot-classification", model=_ZS_MODEL_NAME, device=-1)
        return True
    except Exception as e:
        logging.warning(f"Zero-shot init failed: {e}")
        _ZS_CLASSIFIER = None
        return False

def extract_policy_claims(policy_text: str) -> Dict[str, bool]:
    """
    Primary: use zero-shot transformer to detect claims.
    Fallback: keyword-based detection when transformer unavailable.
    """
    # Short-circuit empty
    if not policy_text or len(policy_text.strip()) < 20:
        return _keyword_extract_claims(policy_text or "")

    # Attempt zero-shot
    ok = _init_zero_shot()
    if not ok or _ZS_CLASSIFIER is None:
        return _keyword_extract_claims(policy_text)

    try:
        classifier = _ZS_CLASSIFIER
        candidate_labels = [
            "collects location data",
            "collects contact data",
            "collects camera or photos",
            "collects microphone or audio",
            "collects storage or files",
            "collects phone numbers or call logs",
            "uses advertising ids or tracking",
            "shares data with third parties or partners",
            "mentions security or encryption"
        ]
        # transformer expects plain text
        res = classifier(policy_text, candidate_labels, multi_label=True, truncation=True)
        # res['scores'] align with candidate_labels
        labels = {lab: score for lab, score in zip(res["labels"], res["scores"])}
        # choose thresholds; 0.35 is moderate
        def label_true(s): return labels.get(s, 0.0) >= 0.35

        return {
            "mentions_location": label_true("collects location data"),
            "mentions_contacts": label_true("collects contact data"),
            "mentions_camera": label_true("collects camera or photos"),
            "mentions_microphone": label_true("collects microphone or audio"),
            "mentions_storage": label_true("collects storage or files"),
            "mentions_phone": label_true("collects phone numbers or call logs"),
            "mentions_ads_tracking": label_true("uses advertising ids or tracking"),
            "mentions_third_parties": label_true("shares data with third parties or partners"),
            "mentions_security": label_true("mentions security or encryption"),
        }
    except Exception as e:
        logging.warning(f"Zero-shot classification error: {e}")
        return _keyword_extract_claims(policy_text)

# keep group_permissions and compute_privacy_risk same as tuned version
SENSITIVE_PERMISSION_GROUPS = {
    "location": [
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "ACCESS_MEDIA_LOCATION", "ACCESS_WIFI_STATE", "NEARBY_WIFI_DEVICES"
    ],
    "contacts": [
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "READ_PROFILE"
    ],
    "camera": [
        "CAMERA", "CAPTURE_VIDEO_OUTPUT", "FOREGROUND_SERVICE_CAMERA"
    ],
    "microphone": [
        "RECORD_AUDIO", "FOREGROUND_SERVICE_MICROPHONE"
    ],
    "storage_media": [
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED",
        "MANAGE_EXTERNAL_STORAGE"
    ],
    "phone": [
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
        "READ_CALL_LOG", "ANSWER_PHONE_CALLS", "MANAGE_OWN_CALLS"
    ],
    "ads_tracking": [
        "AD_ID", "ACCESS_ADSERVICES_AD_ID", "ACCESS_ADSERVICES_ATTRIBUTION"
    ]
}

def group_permissions(permissions: List[str]) -> Dict[str, bool]:
    used_groups = {k: False for k in SENSITIVE_PERMISSION_GROUPS.keys()}
    for perm in permissions:
        suffix = perm.split(".")[-1]
        for group, perm_suffixes in SENSITIVE_PERMISSION_GROUPS.items():
            if any(suffix == p or suffix.endswith(p) for p in perm_suffixes):
                used_groups[group] = True
    return used_groups

def compute_privacy_risk(permissions: List[str], policy_text: str) -> Dict:
    # same tuned algorithm as before but calls extract_policy_claims()
    if not policy_text or len(policy_text.strip()) < 50:
        return {
            "score": 25,
            "level": "HIGH",
            "reasons": ["No or insufficient privacy policy text available for analysis."],
            "claims": {},
            "used_groups": group_permissions(permissions),
        }

    claims = extract_policy_claims(policy_text)
    used_groups = group_permissions(permissions)

    risk_points = 0
    reasons = []

    num_groups_used = sum(1 for v in used_groups.values() if v)

    if num_groups_used >= 5:
        risk_points += 20
        reasons.append("App uses many categories of sensitive data (high data exposure surface).")
    elif num_groups_used >= 3:
        risk_points += 10
        reasons.append("App uses multiple types of sensitive data.")
    elif num_groups_used >= 1:
        risk_points += 5
        reasons.append("App accesses at least one type of sensitive data.")

    def check(group_key, claim_key, label, weight):
        nonlocal risk_points
        if used_groups.get(group_key, False) and not claims.get(claim_key, False):
            risk_points += weight
            reasons.append(f"App accesses {label}, but the privacy policy does not clearly mention it.")

    check("location", "mentions_location", "location data", 10)
    check("contacts", "mentions_contacts", "contacts", 10)
    check("camera", "mentions_camera", "camera", 10)
    check("microphone", "mentions_microphone", "microphone/audio", 10)
    check("storage_media", "mentions_storage", "media/storage", 7)
    check("phone", "mentions_phone", "phone/call information", 7)
    check("ads_tracking", "mentions_ads_tracking", "advertising IDs / tracking", 7)

    if used_groups.get("ads_tracking", False):
        risk_points += 5
        reasons.append("App uses advertising IDs / tracking, which increases profiling and behavioral targeting risk.")

    if not claims.get("mentions_third_parties", False):
        risk_points += 8
        reasons.append("Privacy policy does not clearly describe sharing with third parties or partners.")

    if not claims.get("mentions_security", False):
        risk_points += 5
        reasons.append("Privacy policy does not mention data security or protection measures clearly.")

    if risk_points > 90:
        risk_points = 90

    score = max(0, 100 - risk_points)

    if score >= 75:
        level = "LOW"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    if not reasons:
        reasons.append("No major mismatches or privacy concerns detected based on available information.")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "claims": claims,
        "used_groups": used_groups,
    }
