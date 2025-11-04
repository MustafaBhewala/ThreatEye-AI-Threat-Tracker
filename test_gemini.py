"""
Quick test to verify Gemini API key
"""

import google.generativeai as genai
import json

# Load API key from config
with open('config/config.json', 'r') as f:
    config = json.load(f)
    api_key = config['api_keys']['gemini']

print(f"🔑 Testing Gemini API Key: {api_key[:20]}...")

try:
    genai.configure(api_key=api_key)
    print("✅ API key configured")
    
    # List available models
    print("\n📋 Available models:")
    for model in genai.list_models():
        if 'generateContent' in model.supported_generation_methods:
            print(f"  - {model.name}")
    
    # Try to use the model
    print("\n🧪 Testing content generation...")
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    response = model.generate_content("Say 'Hello from Gemini!'")
    print(f"✅ Response: {response.text}")
    
except Exception as e:
    print(f"❌ Error: {e}")
