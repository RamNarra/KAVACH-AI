# Staging Storage Cost Control Policy

Kavach AI implements a dual cost-control strategy for Firebase Storage APK staging to prevent build-up of temporary files:

1. **Immediate Deletion (Primary)**: The FastAPI server automatically deletes the uploaded APK from Firebase Storage immediately after analysis completes or fails (implemented inside the `finally` block of `main.py`).
2. **Orphan Cleanup Script (Secondary)**: Stale APK files that remain in storage (due to aborted uploads, sudden client disconnects, or unexpected API crashes) are detected and deleted once they exceed **10 minutes of age**.

---

## 1. Running the Orphan Cleanup Script Manually

A dedicated Python script `cleanup_orphan_apks.py` lists objects inside the `apks/` prefix and deletes those older than 10 minutes.

### Setup Prerequisites
Ensure you are using the virtual environment with the required GCP storage client library:
```bash
cd ~/Downloads/Projects/KAVACH\ AI/backend
source venv/bin/activate
```

### Dry Run (Audit Only)
To inspect the bucket and list candidate stale files without deleting them:
```bash
python ../ops/cleanup_orphan_apks.py --dry-run
```

### Direct Execution (Safe Delete)
To execute the scan and delete files older than 10 minutes:
```bash
python ../ops/cleanup_orphan_apks.py
```

---

## 2. Scheduling Automated Executions

To ensure the orphan cleanup script runs consistently in the background, you can schedule it using Linux Cron or Google Cloud Scheduler.

### Option A: Local / VM Linux Cron Job
Add a cron job to run the cleanup script every 10 minutes:
```bash
# Open crontab editor
crontab -e

# Append the following line (update absolute paths as required)
*/10 * * * * /home/p4cketsn1ff3r/Downloads/Projects/KAVACH\ AI/backend/venv/bin/python /home/p4cketsn1ff3r/Downloads/Projects/KAVACH\ AI/ops/cleanup_orphan_apks.py >> /var/log/kavach-cleanup.log 2>&1
```

### Option B: Cloud Scheduler & Cloud Run / Cloud Functions
For a fully serverless cloud deployment:
1. Package the cleanup script into a tiny Cloud Run service or Cloud Function endpoint (e.g. `/api/cleanup` restricted via API key/IAM authentication).
2. Configure **Google Cloud Scheduler** to trigger a HTTPS GET/POST call to that endpoint every 10 minutes using the cron expression:
   `*/10 * * * *`
3. Set the target audience as your cleanup endpoint and attach the appropriate service account OIDC token.

---

## 3. Coarse Fallback (Storage Lifecycle Rule)

As a safety safeguard, a coarse bucket lifecycle rule is applied to delete any files older than 1 day in case the scheduling tasks fail.

Apply the safety fallback rule to your bucket:
```bash
gcloud storage buckets update gs://kavach-ai-497708.firebasestorage.app --lifecycle-file=ops/storage-lifecycle.json
```
