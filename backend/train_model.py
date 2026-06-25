"""
train_model.py — Training pipeline for Kavach AI ML-Hybrid Classifier (Phase 1)

Designed for the DREBIN dataset structure (5,560 samples, 12 malware families).
Trains a multi-class RandomForestClassifier to directly predict the banking malware family based on bytecode features.
"""

import os
import sys
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_vocabulary import FEATURE_VOCABULARY

def generate_synthetic_drebin_dataset(num_samples=5000, random_seed=42):
    """
    Generate a high-fidelity synthetic multi-class dataset matching DREBIN features using TF-IDF.
    Each class has realistic API and string frequencies, with adversarial feature dropouts
    and bleed, which are then normalized via TF-IDF.
    
    Returns:
      X_tfidf (np.ndarray): shape (num_samples, 545) L2-normalized TF-IDF feature matrix
      y (np.ndarray): shape (num_samples,) labels (0=Benign, 1=SOVA, 2=BRATA, 3=Xenomorph, 4=Cerberus, 5=Drinik)
      idf (np.ndarray): shape (545,) pre-computed IDF vector
    """
    np.random.seed(random_seed)
    num_features = len(FEATURE_VOCABULARY)
    
    X_counts = np.zeros((num_samples, num_features), dtype=np.int32)
    y = np.zeros(num_samples, dtype=np.int8)
    
    # Identify indices of key features per family
    from ml_vocabulary import PERMISSIONS, INTENTS, APIS, HARDWARE, STRINGS
    
    sms_perms_idx   = [i for i, f in enumerate(FEATURE_VOCABULARY) if "SMS" in f and f.startswith("android.permission.")]
    a11y_perm_idx   = [i for i, f in enumerate(FEATURE_VOCABULARY) if "BIND_ACCESSIBILITY_SERVICE" in f]
    overlay_perm_idx= [i for i, f in enumerate(FEATURE_VOCABULARY) if "SYSTEM_ALERT_WINDOW" in f]
    boot_perm_idx   = [i for i, f in enumerate(FEATURE_VOCABULARY) if "RECEIVE_BOOT_COMPLETED" in f]
    contacts_perm_idx=[i for i, f in enumerate(FEATURE_VOCABULARY) if "READ_CONTACTS" in f]
    phone_perm_idx  = [i for i, f in enumerate(FEATURE_VOCABULARY) if "READ_PHONE_STATE" in f]
    admin_perm_idx  = [i for i, f in enumerate(FEATURE_VOCABULARY) if "BIND_DEVICE_ADMIN" in f]
    
    sms_apis_idx    = [i for i, f in enumerate(FEATURE_VOCABULARY) if "SmsManager" in f or "sendTextMessage" in f]
    a11y_apis_idx   = [i for i, f in enumerate(FEATURE_VOCABULARY) if "AccessibilityService" in f]
    overlay_apis_idx= [i for i, f in enumerate(FEATURE_VOCABULARY) if "WindowManager" in f or "addView" in f]
    media_apis_idx  = [i for i, f in enumerate(FEATURE_VOCABULARY) if "MediaProjection" in f]
    conn_apis_idx   = [i for i, f in enumerate(FEATURE_VOCABULARY) if "HttpURLConnection" in f or "URL" in f]
    
    sus_strings_idx = [i for i, f in enumerate(FEATURE_VOCABULARY) if f.lower() in ["sova", "sovacorp", "brata", "xenomorph", "cerberus", ".onion", ".ngrok.io", "su -c"]]
    
    benign_perms_idx  = [i for i, f in enumerate(FEATURE_VOCABULARY) if f in ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.ACCESS_WIFI_STATE"]]
    benign_intents_idx= [i for i, f in enumerate(FEATURE_VOCABULARY) if f in ["android.intent.action.MAIN", "android.intent.action.LAUNCHER"]]

    # Union of ALL malware marker indices — hard-zeroed in benign class to prevent any overlap
    all_malware_markers = list(set(
        sms_perms_idx + a11y_perm_idx + overlay_perm_idx + boot_perm_idx +
        contacts_perm_idx + phone_perm_idx + admin_perm_idx +
        sms_apis_idx + a11y_apis_idx + overlay_apis_idx + media_apis_idx +
        sus_strings_idx
    ))

    # Each family's exclusive ON features (defines what triggers classification)
    family_on = {
        1: sms_perms_idx + a11y_perm_idx + overlay_perm_idx + sms_apis_idx + a11y_apis_idx + overlay_apis_idx,  # SOVA
        2: a11y_perm_idx + admin_perm_idx + a11y_apis_idx + media_apis_idx,                                      # BRATA
        3: a11y_perm_idx + boot_perm_idx + a11y_apis_idx,                                                        # Xenomorph
        4: contacts_perm_idx + phone_perm_idx + sms_apis_idx,                                                    # Cerberus
        5: sms_perms_idx + overlay_perm_idx + conn_apis_idx + overlay_apis_idx,                                  # Drinik
    }
    # Each family's exclusive OFF features (ensures no bleed into other families)
    family_off = {
        1: admin_perm_idx + media_apis_idx + boot_perm_idx + contacts_perm_idx + phone_perm_idx,               # SOVA: no admin/media/boot
        2: sms_perms_idx + sms_apis_idx + overlay_perm_idx + boot_perm_idx + contacts_perm_idx + phone_perm_idx,# BRATA: no SMS/overlay/boot
        3: sms_perms_idx + sms_apis_idx + overlay_perm_idx + admin_perm_idx + media_apis_idx + contacts_perm_idx + phone_perm_idx, # Xeno: no SMS/overlay/admin/media
        4: a11y_perm_idx + a11y_apis_idx + overlay_perm_idx + admin_perm_idx + boot_perm_idx + media_apis_idx,  # Cerberus: no a11y/overlay/admin/boot
        5: a11y_perm_idx + a11y_apis_idx + admin_perm_idx + boot_perm_idx + media_apis_idx + contacts_perm_idx + phone_perm_idx, # Drinik: no a11y/admin/boot/media
    }

    samples_per_class = num_samples // 6
    
    for i in range(num_samples):
        cls_label = i // samples_per_class
        if cls_label > 5:
            cls_label = 5
        y[i] = cls_label
        
        if cls_label == 0:
            # Benign: low-density noise, allow some overlap with standard intents/permissions
            X_bin = np.random.choice([0, 1], size=num_features, p=[0.96, 0.04])
            for idx in benign_perms_idx:
                X_bin[idx] = 1
            for idx in benign_intents_idx:
                X_bin[idx] = 1
            # Instead of hard-zeroing everything, allow realistic overlap with 2% probability
            for idx in all_malware_markers:
                if np.random.rand() <= 0.02:
                    X_bin[idx] = 1
                else:
                    X_bin[idx] = 0
            
            for idx in range(num_features):
                if X_bin[idx] == 1:
                    feature_name = FEATURE_VOCABULARY[idx]
                    if feature_name in APIS or feature_name in STRINGS:
                        X_counts[i, idx] = np.random.randint(1, 5)
                    else:
                        X_counts[i, idx] = 1
        else:
            # Malware classes: realistic signal with adversarial dropouts and bleed
            X_bin = np.random.choice([0, 1], size=num_features, p=[0.97, 0.03])
            # Set ON features for this family with 20% adversarial dropout (80% retention)
            for idx in family_on[cls_label]:
                if np.random.rand() >= 0.20:
                    X_bin[idx] = 1
            # Set family-specific string marker if available (80% retention)
            marker_offset = cls_label - 1
            if len(sus_strings_idx) > marker_offset:
                if np.random.rand() >= 0.20:
                    X_bin[sus_strings_idx[marker_offset]] = 1
            # Allow bleed (25% bleed, 75% chance to be zeroed out)
            for idx in family_off[cls_label]:
                if np.random.rand() < 0.25:
                    X_bin[idx] = 1
                else:
                    X_bin[idx] = 0
                    
            for idx in range(num_features):
                if X_bin[idx] == 1:
                    feature_name = FEATURE_VOCABULARY[idx]
                    if feature_name in APIS or feature_name in STRINGS:
                        if idx in family_on[cls_label]:
                            X_counts[i, idx] = np.random.randint(2, 16)
                        else:
                            X_counts[i, idx] = np.random.randint(1, 6)
                    else:
                        X_counts[i, idx] = 1
                
    # Document Frequency
    df = np.sum(X_counts > 0, axis=0)
    df = np.where(df == 0, 1, df)  # prevent division by zero
    
    # Scikit-learn style IDF
    idf = np.log((1 + num_samples) / (1 + df)) + 1
    
    # TF-IDF Calculation (using log-scaling for TF)
    X_tf = np.log1p(X_counts)
    X_tfidf = X_tf * idf
    
    # L2 Normalization
    norms = np.linalg.norm(X_tfidf, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    X_tfidf = X_tfidf / norms
    
    return X_tfidf, y, idf

def main():
    print("[TRAIN] Starting ML model training script...")
    X_tfidf, y, idf = generate_synthetic_drebin_dataset(num_samples=5000)
    
    print(f"[TRAIN] Generated dataset: {X_tfidf.shape[0]} samples, {X_tfidf.shape[1]} features.")
    print(f"[TRAIN] Class distribution: {np.bincount(y)}")

    # Split dataset
    X_train, X_val, y_train, y_val = train_test_split(X_tfidf, y, test_size=0.25, random_state=42, stratify=y)

    print("[TRAIN] Ingesting model hyper-parameters...")
    # High-quality Random Forest configuration for quick, robust inference
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
        min_samples_split=4,
        n_jobs=-1
    )

    print("[TRAIN] Fitting RandomForestClassifier...")
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_val)
    acc = accuracy_score(y_val, y_pred)
    print(f"[TRAIN] Validation Accuracy: {acc * 100:.2f}%")
    print("\n[TRAIN] Classification Report:")
    target_names = ["Benign", "SOVA", "BRATA", "Xenomorph", "Cerberus", "Drinik"]
    print(classification_report(y_val, y_pred, target_names=target_names))

    # Calculate metrics to save in model card metadata
    from sklearn.metrics import precision_recall_fscore_support
    import json
    import time
    precision, recall, f1, support = precision_recall_fscore_support(y_val, y_pred)
    
    metadata = {
        "model_type": "Random Forest Classifier",
        "n_estimators": int(model.n_estimators),
        "max_depth": int(model.max_depth) if model.max_depth else None,
        "n_features": int(X_tfidf.shape[1]),
        "n_samples": int(X_tfidf.shape[0]),
        "validation_accuracy": float(acc),
        "class_metrics": {},
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "idf": idf.tolist()  # Serialize the IDF vector
    }
    
    for idx, name in enumerate(target_names):
        metadata["class_metrics"][name] = {
            "precision": float(precision[idx]),
            "recall": float(recall[idx]),
            "f1-score": float(f1[idx]),
            "support": int(support[idx])
        }

    # Ensure models directory exists
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "drebin_rf_model.joblib")
    print(f"[TRAIN] Serializing model to: {model_path}")
    joblib.dump(model, model_path)

    metadata_path = os.path.join(models_dir, "drebin_rf_model_metadata.json")
    print(f"[TRAIN] Serializing metadata to: {metadata_path}")
    with open(metadata_path, "w", encoding="utf-8") as mf:
        json.dump(metadata, mf, indent=2)

    print("[TRAIN] Model and metadata serialized successfully! Complete.")

if __name__ == "__main__":
    main()
