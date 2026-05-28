import os
import argparse
import datetime
import logging
from google.cloud import storage

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kavach-cleanup")

PROJECT_ID = "kavach-ai-497708"
BUCKET_NAME = f"{PROJECT_ID}.firebasestorage.app"
PREFIX = "apks/"
THRESHOLD_MINUTES = 10

def cleanup_orphaned_apks(dry_run=False):
    logger.info(f"Starting orphan APK cleanup scanner. Bucket: {BUCKET_NAME}, Prefix: {PREFIX}, Threshold: {THRESHOLD_MINUTES} minutes, Dry-run: {dry_run}")
    
    try:
        client = storage.Client(project=PROJECT_ID)
        bucket = client.bucket(BUCKET_NAME)
        blobs = bucket.list_blobs(prefix=PREFIX)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        deleted_count = 0
        skipped_count = 0
        scanned_count = 0
        
        for blob in blobs:
            scanned_count += 1
            # Parse creation time (which is in UTC)
            created_time = blob.time_created
            age = now - created_time
            age_minutes = age.total_seconds() / 60.0
            
            if age_minutes > THRESHOLD_MINUTES:
                logger.info(f"Found stale APK blob: {blob.name} (Age: {age_minutes:.2f} mins, Created: {created_time.isoformat()})")
                if not dry_run:
                    blob.delete()
                    logger.info(f"Deleted stale APK: {blob.name}")
                else:
                    logger.info(f"[DRY-RUN] Would delete stale APK: {blob.name}")
                deleted_count += 1
            else:
                logger.info(f"Skipping fresh APK blob: {blob.name} (Age: {age_minutes:.2f} mins)")
                skipped_count += 1
                
        logger.info(f"Cleanup run complete. Scanned: {scanned_count}, Stale (Deleted/Audited): {deleted_count}, Fresh (Skipped): {skipped_count}")
        
    except Exception as e:
        logger.error(f"Error during cleanup execution: {e}")
        raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean up temporary uploaded APKs older than 10 minutes.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry-run check without actually deleting files.")
    args = parser.parse_args()
    
    cleanup_orphaned_apks(dry_run=args.dry_run)
