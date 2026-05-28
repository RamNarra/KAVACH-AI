import os
import vertexai
from vertexai.generative_models import GenerativeModel

PROJECT_ID = "kavach-ai-497708"

for location in ["global", "us", "eu", "us-central1", "us-east4", "asia-south1"]:
    print(f"\n=== Testing location: {location} ===")
    try:
        vertexai.init(project=PROJECT_ID, location=location)
    except Exception as e:
        print(f"Init failed: {e}")
        continue
        
    for model_name in ["gemini-3.5-flash", "gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]:
        print(f"Testing model: {model_name}...")
        try:
            model = GenerativeModel(model_name)
            response = model.generate_content("Hello, this is a test. Reply with one word.")
            print(f"  SUCCESS! Response: {response.text.strip()}")
            # If success, let's print this is the working configuration
            print(f"  --> WORKING: location={location}, model={model_name}")
        except Exception as e:
            print(f"  FAILED: {e}")
