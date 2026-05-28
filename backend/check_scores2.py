import firebase_admin
from firebase_admin import credentials, firestore

if not firebase_admin._apps:
    firebase_admin.initialize_app(options={'projectId': 'kavach-ai-497708'})

db = firestore.client()
docs = list(db.collection('apkanalysisresults').limit(10).get())
print("SCORES:")
for d in docs[-4:]:
    v = d.to_dict()
    print(f"ID: {d.id} | Score: {v.get('risk_score')} | Threat: {v.get('threat_level')}")
