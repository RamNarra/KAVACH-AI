import pprint

import firebase_admin
import httpx
from firebase_admin import firestore, storage

PROJECT_ID = "kavach-ai-497708"
SESSION_HEADERS = {"X-Kavach-Session": "sess_test_pipeline_operator_1234567890"}


def main() -> None:
    print("Initializing Firebase Admin SDK...")
    if not firebase_admin._apps:
        firebase_admin.initialize_app(options={
            "projectId": PROJECT_ID,
            "storageBucket": f"{PROJECT_ID}.firebasestorage.app",
        })

    bucket = storage.bucket()
    db = firestore.client()
    local_apk_path = "/home/p4cketsn1ff3r/Downloads/InsecureBankv2.apk"

    print(f"Step 1: Uploading local APK ({local_apk_path}) to Firebase Storage...")
    blob = bucket.blob("apks/test_operator/InsecureBankv2.apk")
    blob.upload_from_filename(local_apk_path)
    print("Upload complete.")

    print("Step 2: Making blob public and generating download URL...")
    blob.make_public()
    download_url = blob.public_url
    print(f"Generated public URL: {download_url}")

    print("Step 3: Triggering local static analysis endpoint (http://localhost:8080/api/analyze)...")
    try:
        with httpx.Client(timeout=240.0) as client:
            response = client.post(
                "http://localhost:8080/api/analyze",
                headers=SESSION_HEADERS,
                json={
                    "apk_url": download_url,
                    "email": "operator_test@kavach.ai",
                },
            )
            print(f"Response status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print("\n=== ANALYSIS RESULT SCORECARD ===")
                print(f"Risk Score  : {result.get('risk_score')}/100")
                print(f"Threat Level: {result.get('threat_level')}")
                print(f"Package Name: {result.get('package_name')}")
                print("\nSummary:")
                print(result.get("investigation_report", {}).get("summary"))
                print("\nFirst 3 Permissions analyzed:")
                pprint.pprint(result.get("investigation_report", {}).get("permissions_analysis", [])[:3])
                print("\nFirst 3 Suspicious Activities flagged:")
                pprint.pprint(result.get("investigation_report", {}).get("suspicious_activities", [])[:3])
                print("\nFirst 3 Code Vulnerabilities flagged:")
                pprint.pprint(result.get("investigation_report", {}).get("code_vulnerabilities", [])[:3])

                print("\nStep 4: Verifying Firestore persistence...")
                doc_id = result.get("id")
                doc_ref = db.collection("apkanalysisresults").document(doc_id)
                doc_snapshot = doc_ref.get()
                if doc_snapshot.exists:
                    print(f"Firestore Verification: PASS (Document ID {doc_id} exists)")
                else:
                    print("Firestore Verification: FAIL")
            else:
                print(f"Analysis FAILED. Error details: {response.text}")
    except Exception as e:
        print(f"API post failed: {e}")

    print("\nStep 5: Verifying remote Firebase Storage cleanup...")
    blob_exists = blob.exists()
    if not blob_exists:
        print("Storage Cleanup Verification: PASS (APK deleted from bucket)")
    else:
        print("Storage Cleanup Verification: FAIL (APK still exists)")


if __name__ == "__main__":
    main()
