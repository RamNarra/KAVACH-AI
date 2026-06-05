import firebase_admin
import httpx
from firebase_admin import firestore

PROJECT_ID = "kavach-ai-497708"
SESSION_HEADERS = {"X-Kavach-Session": "sess_test_pipeline_local_1234567890"}


def main() -> None:
    print("Initializing Firebase Admin SDK...")
    if not firebase_admin._apps:
        firebase_admin.initialize_app(options={
            "projectId": PROJECT_ID,
        })

    db = firestore.client()
    download_url = "http://127.0.0.1:8000/InsecureBankv2.apk"
    print(f"Using local server URL: {download_url}")

    print("Step 1: Triggering local static analysis endpoint (http://localhost:8080/api/analyze)...")
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
                print(f"Document ID : {result.get('id')}")

                print("\nStep 2: Verifying Firestore persistence...")
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


if __name__ == "__main__":
    main()
