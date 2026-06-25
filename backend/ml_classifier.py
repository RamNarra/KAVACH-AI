"""
ml_classifier.py — Kavach AI ML-Hybrid Classifier (Phase 1 Inference)

Loads the pre-trained RandomForest model and constructs the 545-dimensional
feature vector from Androguard static results and JADX source files.
"""

import os
import sys
import logging
import numpy as np
import joblib
import xml.etree.ElementTree as ET

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_vocabulary import FEATURE_VOCABULARY, PERMISSIONS, INTENTS, APIS, HARDWARE, STRINGS

logger = logging.getLogger("kavach-ml-classifier")

# Cache the model instance globally to prevent reloading on every scan API call
_MODEL_INSTANCE = None

def get_model():
    """Load and return the pre-trained Random Forest model."""
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        model_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "models", "drebin_rf_model.joblib"
        )
        if os.path.exists(model_path):
            try:
                _MODEL_INSTANCE = joblib.load(model_path)
                logger.info(f"[ML] Model loaded successfully from {model_path}")
            except Exception as e:
                logger.error(f"[ML] Failed to load joblib model: {e}")
        else:
            logger.warning(f"[ML] Pre-trained model not found at {model_path}. ML predictions will fallback.")
    return _MODEL_INSTANCE

_METADATA_INSTANCE = None
def get_model_metadata():
    """Load and return model card metadata."""
    global _METADATA_INSTANCE
    if _METADATA_INSTANCE is None:
        import json
        metadata_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "models", "drebin_rf_model_metadata.json"
        )
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    _METADATA_INSTANCE = json.load(f)
                logger.info(f"[ML] Model metadata loaded successfully from {metadata_path}")
            except Exception as e:
                logger.error(f"[ML] Failed to load model metadata: {e}")
    return _METADATA_INSTANCE

import re

def extract_vector(androguard_result: dict, key_sources: dict = None) -> np.ndarray:
    """
    Extract a 545-dimensional L2-normalized TF-IDF feature vector from APK analysis results.
    
    Args:
      androguard_result (dict): JSON from Androguard static analyzer
      key_sources (dict): Optional dict of {file_path: java_or_smali_source_code}
      
    Returns:
      vector (np.ndarray): 545-dimensional float array (dtype=np.float32)
    """
    key_sources = key_sources or {}
    counts = np.zeros(len(FEATURE_VOCABULARY), dtype=np.float32)
    
    # 1. Manifest data preprocessing
    manifest = androguard_result.get("manifest_content") or ""
    manifest_lower = manifest.lower()
    
    # Extract declared attributes using XML ElementTree
    declared_permissions = set()
    declared_intents = set()
    declared_hardware = set()
    
    if manifest:
        try:
            # Parse XML safely, removing namespaces if present
            root = ET.fromstring(manifest)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag in ("uses-permission", "permission"):
                    for name, val in elem.attrib.items():
                        if name.split('}')[-1] == "name":
                            declared_permissions.add(val.strip())
                elif tag == "action":
                    for name, val in elem.attrib.items():
                        if name.split('}')[-1] == "name":
                            declared_intents.add(val.strip())
                elif tag == "uses-feature":
                    for name, val in elem.attrib.items():
                        if name.split('}')[-1] == "name":
                            declared_hardware.add(val.strip())
        except Exception as et_err:
            logger.warning(f"[ML] XML ElementTree parsing failed, falling back to regex: {et_err}")
            # Fallback to regex checks
            for m in re.finditer(r'<(?:uses-)?permission\s+[^>]*android:name=["\'\s]*([^"\'\s>]+)', manifest):
                declared_permissions.add(m.group(1).strip())
            for m in re.finditer(r'<action\s+[^>]*android:name=["\'\s]*([^"\'\s>]+)', manifest):
                declared_intents.add(m.group(1).strip())
            for m in re.finditer(r'<uses-feature\s+[^>]*android:name=["\'\s]*([^"\'\s>]+)', manifest):
                declared_hardware.add(m.group(1).strip())
    
    # 2. Suspicious bytecode strings preprocessing
    bytecode_strings = [str(s).lower() for s in androguard_result.get("suspicious_strings", [])]
    
    # 3. Source files preprocessing (categorize Java vs Smali)
    java_sources = []
    smali_sources = []
    for path, code in key_sources.items():
        code_lower = code.lower()
        if code.strip().startswith('.') or '.method' in code or '.field' in code:
            smali_sources.append(code_lower)
        else:
            java_sources.append(code_lower)
            
    all_sources_lower = "\n".join(java_sources + smali_sources)
    
    # Iterate over the vocabulary and check presence/count of each feature
    for idx, feature in enumerate(FEATURE_VOCABULARY):
        feat_lower = feature.lower()
        
        # Category 1: Permissions (checked in manifest)
        if feature in PERMISSIONS:
            if feature in declared_permissions or feat_lower in declared_permissions:
                counts[idx] = 1.0
            elif f'android:name="{feat_lower}"' in manifest_lower or f"android:name='{feat_lower}'" in manifest_lower:
                counts[idx] = 1.0
                
        # Category 2: Intent Actions (checked in manifest)
        elif feature in INTENTS:
            if feature in declared_intents or feat_lower in declared_intents:
                counts[idx] = 1.0
            elif f'android:name="{feat_lower}"' in manifest_lower or f"android:name='{feat_lower}'" in manifest_lower:
                counts[idx] = 1.0
                
        # Category 3: APIs (checked in sources, bytecode strings, or API chain descriptions)
        elif feature in APIS:
            if "->" in feature:
                parts = feature.split("->")
                class_part = parts[0].strip("L;")  # e.g. android/telephony/SmsManager
                member_part = parts[1]             # e.g. sendTextMessage
                class_simple_name = class_part.split("/")[-1].lower()
                member_lower = member_part.lower()
                
                # Smali sources: check signature or class + member
                for smali in smali_sources:
                    if feat_lower in smali or (class_simple_name in smali and member_lower in smali):
                        counts[idx] += max(1.0, float(smali.count(feat_lower) or smali.count(member_lower)))
                
                # Java sources: check simple class name + member name
                for java in java_sources:
                    if class_simple_name in java and member_lower in java:
                        counts[idx] += max(1.0, float(java.count(member_lower)))
            else:
                if feat_lower in all_sources_lower:
                    counts[idx] += max(1.0, float(all_sources_lower.count(feat_lower)))
            
            # Check Androguard's detected API chains
            for chain in androguard_result.get("dangerous_api_chains", []):
                chain_desc = str(chain.get("description", "")).lower()
                short_api = feat_lower.split("->")[-1] if "->" in feat_lower else feat_lower
                if short_api in chain_desc:
                    counts[idx] += 1.0
                        
        # Category 4: Hardware Requirements (checked in manifest)
        elif feature in HARDWARE:
            if feature in declared_hardware or feat_lower in declared_hardware:
                counts[idx] = 1.0
            elif f'android:name="{feat_lower}"' in manifest_lower or f"android:name='{feat_lower}'" in manifest_lower:
                counts[idx] = 1.0
                
        # Category 5: Suspicious Strings (checked in bytecode strings, manifest, or source corpus)
        elif feature in STRINGS:
            for s in bytecode_strings:
                if feat_lower in s:
                    counts[idx] += 1.0
            if feat_lower in all_sources_lower:
                counts[idx] += float(all_sources_lower.count(feat_lower))
            if feat_lower in manifest_lower:
                counts[idx] += float(manifest_lower.count(feat_lower))
                
    # Transform raw counts to TF (log scaled)
    tf = np.log1p(counts)
    
    # Apply pre-computed IDF vector from model metadata
    metadata = get_model_metadata()
    if metadata and "idf" in metadata:
        idf = np.array(metadata["idf"], dtype=np.float32)
    else:
        idf = np.ones(len(FEATURE_VOCABULARY), dtype=np.float32)
        
    tf_idf = tf * idf
    
    # L2 Normalization
    norm = np.linalg.norm(tf_idf)
    if norm > 0:
        tf_idf = tf_idf / norm
        
    return tf_idf

def predict_apk_risk(androguard_result: dict, key_sources: dict = None) -> dict:
    """
    Run machine learning classification on the target APK.
    
    Returns:
      dict: {
        "is_malicious": bool,
        "ml_confidence_score": float (0.0-1.0),
        "predicted_malware_family": str (e.g., SOVA, BRATA, or BENIGN),
        "matching_features_count": int
      }
    """
    result = {
        "is_malicious": False,
        "ml_confidence_score": 0.0,
        "predicted_malware_family": "BENIGN",
        "matching_features_count": 0,
        "status": "SKIPPED"
    }
    
    if not androguard_result:
        result["status"] = "ERROR_NO_STATIC_DATA"
        return result
        
    model = get_model()
    if not model:
        result["status"] = "ERROR_MODEL_UNAVAILABLE"
        return result
        
    # Extract feature vector
    vector = extract_vector(androguard_result, key_sources)
    matching_count = int(np.sum(vector > 0))
    result["matching_features_count"] = matching_count
    
    try:
        # Reshape for single prediction
        X_pred = vector.reshape(1, -1)
        
        # 1. Predict class probabilities
        probs = model.predict_proba(X_pred)[0]
        # Sum of probabilities of all malicious classes (1 to 5)
        malware_probability = float(np.sum(probs[1:]))
        
        # 2. Predict multi-class label directly using Random Forest
        pred_label = int(model.predict(X_pred)[0])
        
        family_mapping = {
            0: "BENIGN",
            1: "SOVA",
            2: "BRATA",
            3: "Xenomorph",
            4: "Cerberus",
            5: "Drinik"
        }
        
        result["ml_confidence_score"] = malware_probability
        result["is_malicious"] = (pred_label > 0)
        result["status"] = "SUCCESS"
        result["predicted_malware_family"] = family_mapping.get(pred_label, "Generic Banking Trojan")
        result["family_classification_method"] = "Random Forest Multi-Class Output"
        
        # 4. Extract top 5 feature attributions based on model importances
        top_features = []
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            present_indices = np.where(vector == 1)[0]
            feature_contribs = []
            for idx in present_indices:
                feature_name = FEATURE_VOCABULARY[idx]
                importance_score = float(importances[idx])
                feature_contribs.append((feature_name, importance_score))
            # Sort descending by model importance score
            feature_contribs.sort(key=lambda x: x[1], reverse=True)
            top_features = [{"feature": f[0], "importance": f[1]} for f in feature_contribs[:5]]
        result["top_features"] = top_features
        
        # Inject model card validation metadata
        metadata = get_model_metadata()
        if metadata:
            result["model_metadata"] = metadata
            
        logger.info(f"[ML] Random Forest multi-class inference complete. Predicted: {result['predicted_malware_family']} (conf={malware_probability:.2f})")
            
    except Exception as e:
        logger.error(f"[ML] Inference failed: {e}")
        result["status"] = "ERROR_INFERENCE_FAILED"
        result["error"] = str(e)
        
    return result
