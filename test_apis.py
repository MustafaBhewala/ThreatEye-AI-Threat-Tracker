"""
API Connection Test Script
Tests connectivity to all three threat intelligence APIs
"""

import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_virustotal():
    """Test VirusTotal API connection"""
    print("\n🧪 Testing VirusTotal API...")
    try:
        import requests
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        headers = {
            'x-apikey': api_key
        }
        
        # Test with a known malicious IP (Google's DNS for testing - safe)
        response = requests.get(
            'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ VirusTotal API: Connected Successfully!")
            print(f"   Response: Got data for IP 8.8.8.8")
            return True
        else:
            print(f"❌ VirusTotal API: Failed (Status: {response.status_code})")
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ VirusTotal API: Error - {str(e)}")
        return False


def test_abuseipdb():
    """Test AbuseIPDB API connection"""
    print("\n🧪 Testing AbuseIPDB API...")
    try:
        import requests
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        
        # Test with Google's DNS (safe test)
        params = {
            'ipAddress': '8.8.8.8',
            'maxAgeInDays': '90'
        }
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ AbuseIPDB API: Connected Successfully!")
            print(f"   Response: Got data for IP 8.8.8.8")
            print(f"   Abuse Confidence Score: {data['data']['abuseConfidenceScore']}%")
            return True
        else:
            print(f"❌ AbuseIPDB API: Failed (Status: {response.status_code})")
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ AbuseIPDB API: Error - {str(e)}")
        return False


def test_otx():
    """Test AlienVault OTX API connection"""
    print("\n🧪 Testing AlienVault OTX API...")
    try:
        from OTXv2 import OTXv2
        api_key = os.getenv('OTX_API_KEY')
        
        otx = OTXv2(api_key)
        
        # Test by getting general info about an IP
        result = otx.get_indicator_details_full('IPv4', '8.8.8.8')
        
        if result:
            print("✅ AlienVault OTX API: Connected Successfully!")
            print(f"   Response: Got data for IP 8.8.8.8")
            
            # Check if there are any pulses
            if 'general' in result and 'pulse_info' in result['general']:
                pulse_count = result['general']['pulse_info']['count']
                print(f"   Threat Pulses: {pulse_count}")
            
            return True
        else:
            print("❌ AlienVault OTX API: No data returned")
            return False
            
    except Exception as e:
        print(f"❌ AlienVault OTX API: Error - {str(e)}")
        return False


def main():
    """Run all API tests"""
    print("=" * 60)
    print("🛡️  ThreatEye API Connection Test")
    print("=" * 60)
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("\n❌ Error: .env file not found!")
        print("   Please create .env file with your API keys")
        return
    
    print("\n📋 Loaded API Keys:")
    print(f"   ✓ VirusTotal: {os.getenv('VIRUSTOTAL_API_KEY')[:20]}...")
    print(f"   ✓ AbuseIPDB: {os.getenv('ABUSEIPDB_API_KEY')[:20]}...")
    print(f"   ✓ OTX: {os.getenv('OTX_API_KEY')[:20]}...")
    
    print("\n" + "=" * 60)
    print("Running API Connection Tests...")
    print("=" * 60)
    
    results = {
        'VirusTotal': test_virustotal(),
        'AbuseIPDB': test_abuseipdb(),
        'AlienVault OTX': test_otx()
    }
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    for api_name, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"   {api_name}: {status}")
    
    total_passed = sum(results.values())
    print(f"\n   Total: {total_passed}/3 APIs working")
    
    if total_passed == 3:
        print("\n🎉 All APIs are working! Ready to start building ThreatEye!")
    elif total_passed > 0:
        print(f"\n⚠️  {total_passed} API(s) working. You can proceed with available APIs.")
    else:
        print("\n❌ No APIs working. Please check your API keys.")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
