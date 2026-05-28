import os
import tempfile
import subprocess
import shutil
import json
import logging
import httpx
import uuid
import datetime
import xml.etree.ElementTree as ET
import threading
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import firebase_admin
from firebase_admin import credentials, firestore, storage as firebase_storage
from google import genai
from google.genai import types as genai_types

from analysis_engine import calculate_deterministic_score

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kavach-api")

# Add virtual environment bin directory to PATH for local execution of apktool/jadx/quark
venv_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin")
if os.path.exists(venv_bin):
    os.environ["PATH"] = f"{venv_bin}{os.pathsep}{os.environ['PATH']}"
    logger.info(f"Dynamic tools PATH addition: {venv_bin}")

# Load environment configurations
PROJECT_ID = os.environ.get("PROJECT_ID", "kavach-ai-497708")
LOCATION = os.environ.get("LOCATION", "global")
MODEL_NAME = "gemini-3.5-flash"  # Exactly gemini-3.5-flash as required

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    try:
        # Initialize Firebase Admin with storage bucket for remote cleanup
        firebase_admin.initialize_app(options={
            "projectId": PROJECT_ID,
            "storageBucket": f"{PROJECT_ID}.firebasestorage.app"
        })
        logger.info("Firebase Admin initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing Firebase Admin: {e}")
        firebase_admin.initialize_app()

db = firestore.client()

# Initialize Google Gen AI client (Vertex AI backend)
try:
    genai_client = genai.Client(
        vertexai=True,
        project=PROJECT_ID,
        location=LOCATION,
    )
    logger.info(f"Google Gen AI client (Vertex AI) initialized — project={PROJECT_ID}, location={LOCATION}")
except Exception as e:
    logger.error(f"Error initializing Google Gen AI client: {e}")
    genai_client = None

# Initialize FastAPI App
app = FastAPI(
    title="Kavach AI API",
    description="Generative AI-Based APK Malware Analysis Backend",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    apk_url: str
    email: str | None = None
    uid: str | None = None

def parse_package_name(apktool_dir: str) -> str:
    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return ""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        return root.attrib.get("package", "")
    except Exception as e:
        logger.error(f"Error parsing AndroidManifest.xml package: {e}")
        return ""

def select_key_java_files(jadx_dir: str, package_name: str) -> tuple[Dict[str, str], List[str]]:
    sources_dir = os.path.join(jadx_dir, "sources")
    key_files = {}
    all_paths = []
    
    if not os.path.exists(sources_dir):
        return key_files, all_paths

    for root, _, files in os.walk(sources_dir):
        for file in files:
            if file.endswith(".java"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, sources_dir)
                all_paths.append(rel_path)

    package_path = package_name.replace(".", os.sep) if package_name else ""
    target_files = []
    for rel_path in all_paths:
        full_path = os.path.join(sources_dir, rel_path)
        if not package_path or package_path in rel_path:
            target_files.append((rel_path, full_path))
            
    if not target_files:
        target_files = [(rel_path, os.path.join(sources_dir, rel_path)) for rel_path in all_paths]

    keywords = [
        "http", "url", "socket", "webview", "exec", "runtime", "loadlibrary", 
        "cipher", "encrypt", "decrypt", "key", "sms", "location", "telephony",
        "deviceid", "getimei", "install", "shell", "su", "root", "contacts",
        "dexclassloader", "sharedpreferences", "broadcast", "receiver", "service"
    ]

    scored_files = []
    for rel_path, full_path in target_files:
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
                score = sum(content.count(kw) for kw in keywords)
                if "mainactivity" in rel_path.lower():
                    score += 15
                scored_files.append((score, rel_path, full_path))
        except Exception:
            continue

    scored_files.sort(key=lambda x: x[0], reverse=True)

    total_characters = 0
    max_total_characters = 70000

    for score, rel_path, full_path in scored_files[:12]:
        if total_characters >= max_total_characters:
            break
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                code_snippet = "".join(lines[:150])
                if len(lines) > 150:
                    code_snippet += "\n// ... [Remainder of code truncated for analysis limit] ..."
                
                if total_characters + len(code_snippet) > max_total_characters:
                    allowed_length = max_total_characters - total_characters
                    code_snippet = code_snippet[:allowed_length] + "\n// ... [Remainder truncated] ..."
                
                key_files[rel_path] = code_snippet
                total_characters += len(code_snippet)
        except Exception:
            continue

    return key_files, all_paths

def delete_storage_object(apk_url: str):
    try:
        bucket = firebase_storage.bucket()
        blob_path = None

        if apk_url.startswith("gs://"):
            parsed = urlparse(apk_url)
            blob_path = parsed.path.lstrip('/')
        elif "firebasestorage.googleapis.com" in apk_url:
            parsed = urlparse(apk_url)
            path_parts = parsed.path.split('/o/')
            if len(path_parts) > 1:
                encoded_path = path_parts[1].split('?')[0]
                blob_path = unquote(encoded_path)
        elif "storage.googleapis.com" in apk_url:
            parsed = urlparse(apk_url)
            path = parsed.path.lstrip('/')
            bucket_name = bucket.name
            if path.startswith(bucket_name + "/"):
                blob_path = path[len(bucket_name) + 1:]

        if blob_path:
            logger.info(f"Initiating remote storage cleanup for: {blob_path}")
            blob = bucket.blob(blob_path)
            blob.delete()
            logger.info("Remote storage cleanup completed successfully.")
        else:
            logger.warning(f"Could not extract Storage path from APK URL: {apk_url}")
    except Exception as e:
        logger.error(f"Failed to execute remote storage cleanup: {e}")

def clean_and_parse_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from Gemini: {e}")
        return {}

def run_analysis_pipeline(doc_id: str, request: AnalysisRequest):
    apk_url = request.apk_url
    logger.info(f"Starting analysis pipeline for {doc_id}")
    
    doc_ref = db.collection("apkanalysisresults").document(doc_id)

    db_lock = threading.Lock()
    def update_progress(step: str, status: str, log: str = None):
        with db_lock:
            updates = {f"progress.{step}": status}
            if log:
                updates["logs"] = firestore.ArrayUnion([f"[{step.upper()}] {log}"])
            doc_ref.update(updates)

    filename = "unknown_target.apk"
    try:
        parsed_url = urlparse(apk_url)
        path = unquote(parsed_url.path)
        if '/' in path:
            filename = path.split('/')[-1]
            if '?' in filename:
                filename = filename.split('?')[0]
    except Exception:
        pass

    temp_dir = tempfile.mkdtemp(dir="/tmp")
    apk_path = os.path.join(temp_dir, "target.apk")
    apktool_out = os.path.join(temp_dir, "apktool_out")
    jadx_out = os.path.join(temp_dir, "jadx_out")
    quark_json_path = os.path.join(temp_dir, "quark_report.json")

    package_name = ""
    manifest_content = ""
    key_sources = {}
    all_source_files = []
    apktool_error = None
    jadx_error = None

    try:
        update_progress("upload", "COMPLETED", f"Started analysis for {filename}")

        update_progress("download", "RUNNING", "Downloading APK from Firebase...")
        with httpx.Client() as client:
            response = client.get(apk_url, timeout=60.0)
            if response.status_code != 200:
                raise Exception(f"Failed to fetch APK from URL. Status code: {response.status_code}")
            with open(apk_path, "wb") as f:
                f.write(response.content)

        if os.path.getsize(apk_path) < 1024:
            raise Exception("Sanity check failed: File size is less than 1KB.")
        update_progress("download", "COMPLETED", "APK download complete.")

        # Thread targets for parallel execution
        def run_apktool():
            nonlocal package_name, manifest_content, apktool_error
            update_progress("apktool", "RUNNING", "Running APKTool for manifest & resources...")
            try:
                apktool_cmd = ["apktool", "d", "-s", "-f", "-o", apktool_out, apk_path]
                apktool_proc = subprocess.run(apktool_cmd, capture_output=True, text=True, timeout=60)
                if apktool_proc.returncode != 0:
                    raise Exception(f"APKTool decoding failed: {apktool_proc.stderr}")
                
                manifest_file = os.path.join(apktool_out, "AndroidManifest.xml")
                if os.path.exists(manifest_file):
                    with open(manifest_file, "r", encoding="utf-8", errors="ignore") as f:
                        manifest_content = f.read()
                package_name = parse_package_name(apktool_out)
                update_progress("apktool", "COMPLETED", f"APKTool complete. Package: {package_name}")
            except Exception as e:
                apktool_error = e
                update_progress("apktool", "FAILED", f"APKTool failed: {str(e)}")

        def run_jadx():
            nonlocal jadx_error
            update_progress("jadx", "RUNNING", "Running JADX for decompiled Java sources...")
            try:
                jadx_cmd = ["jadx", "--no-res", "-d", jadx_out, apk_path]
                jadx_proc = subprocess.run(jadx_cmd, capture_output=True, text=True, timeout=90)
                if jadx_proc.returncode != 0:
                    raise Exception(f"JADX decompilation failed: {jadx_proc.stderr}")
                update_progress("jadx", "COMPLETED", "JADX decompilation complete.")
            except Exception as e:
                jadx_error = e
                update_progress("jadx", "FAILED", f"JADX failed: {str(e)}")

        def run_quark():
            update_progress("quark", "RUNNING", "Running Quark Engine for malware rule signatures...")
            try:
                quark_cmd = ["quark", "-a", apk_path, "-s", "-o", quark_json_path]
                subprocess.run(quark_cmd, capture_output=True, text=True, timeout=120)
                update_progress("quark", "COMPLETED", "Quark Engine analysis complete.")
            except Exception as e:
                logger.warning(f"Quark engine failed: {e}")
                update_progress("quark", "FAILED", f"Quark Engine failed: {str(e)}")

        # Start parallel decompile/rule execution threads
        t_apktool = threading.Thread(target=run_apktool)
        t_jadx = threading.Thread(target=run_jadx)
        t_quark = threading.Thread(target=run_quark)

        t_apktool.start()
        t_jadx.start()
        t_quark.start()

        t_apktool.join()
        t_jadx.join()
        t_quark.join()

        if apktool_error:
            raise apktool_error
        if jadx_error:
            raise jadx_error

        # Select key java files after decompilation completes
        key_sources, all_source_files = select_key_java_files(jadx_out, package_name)
        update_progress("jadx", "COMPLETED", f"JADX analysis complete. Selected {len(key_sources)} key files.")

        # Calculate deterministic score & structured evidence
        deterministic_result = calculate_deterministic_score(manifest_content, key_sources, quark_json_path)
        det_score = deterministic_result["risk_score"]
        det_threat = deterministic_result["threat_level"]
        evidentiary_details = "\n".join(
            deterministic_result["details"]["manifest"] + 
            deterministic_result["details"]["jadx"] + 
            deterministic_result["details"]["quark"]
        )

        update_progress("gemini", "RUNNING", f"Dispatching to Gemini (Base Score: {det_score}/100)")

        prompt = f"""
You are Kavach AI, an elite Android malware researcher.
We have statically analyzed the app and calculated a deterministic baseline risk score of {det_score}/100 with a threat level of {det_threat}.
Below are the evidentiary findings from our local engines (APKTool, JADX, Quark):

--- DETERMINISTIC FINDINGS ---
{evidentiary_details}

--- ANDROIDMANIFEST.XML ---
{manifest_content}

--- KEY JAVA CODE SNIPPETS ---
"""
        for filepath, code in key_sources.items():
            prompt += f"\nFile: {filepath}\n```java\n{code}\n```\n"

        prompt += f"""
--- ANALYSIS INSTRUCTIONS ---
Your job is to act as the summarizer, explainer, and recommendation generator.
DO NOT change the risk score or threat level. Use the exact score ({det_score}) and level ("{det_threat}") provided.
Synthesize the deterministic findings and provide a professional, analyst-friendly explanation.

You must respond in strict JSON format. 
Response schema configuration:
{{
  "risk_score": {det_score},
  "threat_level": "{det_threat}",
  "investigation_report": {{
    "summary": "<string>",
    "permissions_analysis": [
      {{ "permission": "<string>", "status": "<string>", "description": "<string>" }}
    ],
    "suspicious_activities": [
      {{ "title": "<string>", "description": "<string>", "severity": "<string>", "file": "<string>" }}
    ],
    "code_vulnerabilities": [
      {{ "title": "<string>", "description": "<string>", "severity": "<string>", "file": "<string>" }}
    ],
    "recommendations": ["<string>"]
  }}
}}
Do not return any markdown wraps. Return only raw JSON.
"""

        gen_config = genai_types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
        )

        ai_response = genai_client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=gen_config,
        )
        
        analysis_json = clean_and_parse_json(ai_response.text)
        update_progress("gemini", "COMPLETED", "Gemini synthesis complete.")
        
        analysis_json["risk_score"] = det_score
        analysis_json["threat_level"] = det_threat

        update_progress("finalize", "RUNNING", "Saving final report to database...")
        
        now_str = datetime.datetime.utcnow().isoformat() + "Z"

        final_data = {
            "status": "COMPLETED",
            "filename": filename,
            "apk_url": apk_url,
            "package_name": package_name,
            "risk_score": det_score,
            "threat_level": det_threat,
            "evidence": deterministic_result["evidence"],
            "investigation_report": analysis_json.get("investigation_report", {}),
            "created_at": now_str,
            "uid": request.uid,
            "email": request.email,
            "progress": {
                "upload": "COMPLETED",
                "download": "COMPLETED",
                "apktool": "COMPLETED",
                "jadx": "COMPLETED",
                "quark": "COMPLETED",
                "gemini": "COMPLETED",
                "finalize": "COMPLETED"
            },
            "logs": firestore.ArrayUnion(["[SYS] Analysis complete and saved."])
        }
        doc_ref.update(final_data)
        logger.info(f"Analysis completed successfully for {doc_id}")
        
        return doc_ref.get().to_dict()

    except Exception as e:
        logger.error(f"Pipeline error for {doc_id}: {e}")
        doc_ref.update({
            "status": "FAILED",
            "error_message": str(e),
            "logs": firestore.ArrayUnion([f"[ERROR] {str(e)}"])
        })
        raise e
    finally:
        delete_storage_object(apk_url)
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info(f"Cleaned up temp directory for {doc_id}")

@app.get("/")
@app.get("/api")
def read_root():
    return {"status": "healthy", "service": "Kavach AI Malware Analysis"}

@app.get("/health")
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "Kavach AI", "database": "connected"}

@app.get("/api/history")
def get_history(uid: str):
    if not uid:
        raise HTTPException(status_code=400, detail="Missing uid parameter")
    try:
        docs = db.collection("apkanalysisresults")\
            .where("uid", "==", uid)\
            .order_by("created_at", direction=firestore.Query.DESCENDING)\
            .limit(50)\
            .stream()
        history_list = []
        for doc in docs:
            data = doc.to_dict()
            if "created_at" in data and isinstance(data["created_at"], datetime.datetime):
                data["created_at"] = data["created_at"].isoformat() + "Z"
            history_list.append(data)
        return history_list
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analysis/{id}")
def get_analysis(id: str):
    try:
        doc_ref = db.collection("apkanalysisresults").document(id)
        snapshot = doc_ref.get()
        if not snapshot.exists:
            raise HTTPException(status_code=404, detail="Analysis not found")
        data = snapshot.to_dict()
        if "created_at" in data and isinstance(data["created_at"], datetime.datetime):
            data["created_at"] = data["created_at"].isoformat() + "Z"
        return data
    except Exception as e:
        logger.error(f"Error fetching analysis doc: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze")
def analyze_apk(request: AnalysisRequest, background_tasks: BackgroundTasks, background: bool = False):
    apk_url = request.apk_url
    logger.info(f"Received analysis request for URL: {apk_url} (background={background})")
    
    if not (apk_url.startswith("http://") or apk_url.startswith("https://") or apk_url.startswith("gs://")):
        raise HTTPException(status_code=400, detail="Invalid URL format. URL must start with http, https or gs.")

    doc_ref = db.collection("apkanalysisresults").document()
    doc_id = doc_ref.id

    now_str = datetime.datetime.utcnow().isoformat() + "Z"
    
    initial_doc = {
        "id": doc_id,
        "status": "PROCESSING",
        "created_at": now_str,
        "uid": request.uid,
        "email": request.email,
        "progress": {
            "upload": "COMPLETED",
            "download": "WAITING",
            "apktool": "WAITING",
            "jadx": "WAITING",
            "quark": "WAITING",
            "gemini": "WAITING",
            "finalize": "WAITING"
        },
        "logs": []
    }
    doc_ref.set(initial_doc)

    if background:
        background_tasks.add_task(run_analysis_pipeline, doc_id, request)
        return initial_doc
    else:
        try:
            final_doc = run_analysis_pipeline(doc_id, request)
            return final_doc
        except Exception as e:
            logger.error(f"Analysis endpoint failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
