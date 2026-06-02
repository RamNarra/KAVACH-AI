import os
import time
import datetime
import pprint
import httpx
import firebase_admin
from firebase_admin import credentials, storage, firestore

PROJECT_ID = "kavach-ai-497708"
OPERATOR_UID = "test_operator_123"

print("Initializing Firebase Admin SDK...")
if not firebase_admin._apps:
    firebase_admin.initialize_app(options={
        'projectId': PROJECT_ID,
        'storageBucket': f"{PROJECT_ID}.firebasestorage.app"
    })

bucket = storage.bucket()
db = firestore.client()

local_apk_path = "/home/p4cketsn1ff3r/Downloads/InsecureBankv2.apk"
if not os.path.exists(local_apk_path):
    print(f"Error: Local APK not found at {local_apk_path}")
    exit(1)

# Step 1: Upload APK to Firebase Storage
print(f"Step 1: Uploading local APK ({local_apk_path}) to Firebase Storage...")
blob = bucket.blob("apks/test_operator/InsecureBankv2_dynamic_test.apk")
blob.upload_from_filename(local_apk_path)
print("Upload complete.")

# Step 2: Make Blob Public and Get Public URL
print("Step 2: Making blob public and generating download URL...")
blob.make_public()
download_url = blob.public_url
print(f"Generated public URL: {download_url}")

# Step 3: Trigger Local FastAPI Backend Static Analysis
print("Step 3: Triggering local static analysis endpoint (http://localhost:8080/api/analyze)...")
doc_id = None
try:
    with httpx.Client(timeout=240.0) as client:
        response = client.post(
            "http://localhost:8080/api/analyze",
            json={
                "apk_url": download_url,
                "email": "operator_test@kavach.ai",
                "uid": OPERATOR_UID
            }
        )
        print(f"Static Analysis trigger status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            doc_id = result.get('id')
            print(f"Baseline Risk Score: {result.get('risk_score')}/100")
            print(f"Document ID: {doc_id}")
        else:
            print(f"Static Analysis FAILED: {response.text}")
            exit(1)
except Exception as e:
    print(f"API post failed: {e}")
    exit(1)

if not doc_id:
    print("Failed to acquire Document ID. Exiting.")
    exit(1)

# Step 3.5: Waiting for static analysis to complete in the background...
print("\nStep 3.5: Waiting for static analysis to complete in the background...")
doc_ref = db.collection('apkanalysisresults').document(doc_id)
start_static = time.time()
static_completed = False
while time.time() - start_static < 180:
    doc_snap = doc_ref.get()
    if doc_snap.exists:
        doc_data = doc_snap.to_dict()
        prog = doc_data.get("progress", {})
        finalize_status = prog.get("finalize")
        print(f"[{int(time.time() - start_static)}s] Static progress - JADX: {prog.get('jadx')} | Quark: {prog.get('quark')} | Finalize: {finalize_status}")
        if finalize_status == "COMPLETED":
            static_completed = True
            break
        if finalize_status == "FAILED" or doc_data.get("status") == "FAILED":
            print("Static analysis failed!")
            break
    time.sleep(5)

if not static_completed:
    print("Static analysis did not complete in time or failed. Exiting.")
    exit(1)
print("Static analysis completed successfully!")

# Step 4: Trigger Dynamic Analysis
print(f"\nStep 4: Triggering dynamic analysis on doc {doc_id}...")
try:
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"http://localhost:8080/api/analysis/{doc_id}/dynamic",
            json={"uid": OPERATOR_UID}
        )
        print(f"Dynamic Analysis trigger status: {response.status_code}")
        print(f"Trigger response: {response.json()}")
except Exception as e:
    print(f"API dynamic post failed: {e}")
    exit(1)

# Step 5: Poll Firestore until Dynamic Analysis is complete
print("\nStep 5: Polling Firestore document progress. waiting for dynamic run completion...")
doc_ref = db.collection('apkanalysisresults').document(doc_id)

max_poll_seconds = 180
poll_interval = 5
start_time = time.time()

completed = False
while time.time() - start_time < max_poll_seconds:
    doc_snap = doc_ref.get()
    if not doc_snap.exists:
        print("Document deleted or not found!")
        break
    
    doc_data = doc_snap.to_dict()
    progress = doc_data.get("progress", {})
    dyn_status = progress.get("dynamic_sandbox")
    gemini_status = progress.get("gemini")
    
    print(f"[{int(time.time() - start_time)}s elapsed] Sandbox: {dyn_status} | Gemini Synthesis: {gemini_status}")
    
    if dyn_status == "FAILED":
        print("Dynamic sandbox failed!")
        break
    
    if dyn_status == "COMPLETED" and gemini_status == "COMPLETED":
        completed = True
        break
        
    time.sleep(poll_interval)

if completed:
    print("\n=== DYNAMIC ANALYSIS PIPELINE SUCCESS ===")
    doc_data = doc_ref.get().to_dict()
    
    dynamic_report = doc_data.get("dynamic_analysis", {})
    print(f"Dynamic Status: {dynamic_report.get('status')}")
    print(f"Total events: {dynamic_report.get('event_count', 0)}")
    print(f"Confidence: {dynamic_report.get('runtime_confidence')}")
    
    print("\n--- Playbook Trigger Steps Transcript ---")
    trigger_transcript = dynamic_report.get("trigger_transcript", [])
    for step in trigger_transcript:
        print(f"Step: {step.get('step')} | Action: {step.get('action')} | Result: {step.get('result')}")
        
    print("\n--- Final Gemini Integrated Summary ---")
    print(doc_data.get("investigation_report", {}).get("summary"))
    
    print("\n--- Final Risk Decomposition ---")
    print(f"Final Risk Score: {doc_data.get('risk_score')}/100")
    print(f"Threat Level: {doc_data.get('threat_level')}")
else:
    print("\nPipeline timed out or failed before completion.")

# Cleanup remote Storage object just in case
try:
    blob.delete()
    print("Storage Cleanup successful.")
except Exception:
    pass
