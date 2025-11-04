"""
Database initialization and seeding script
Creates tables and optionally adds sample data for testing
"""

import sys
import os
from datetime import datetime, timedelta
import random

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db_manager, init_database, reset_database
from storage.models import (
    ThreatIndicator, FeedData, EnrichmentData, MLPrediction,
    Alert, UserActivity, ScanJob, Report, SystemConfig,
    ThreatCategory, RiskLevel, IndicatorType, FeedSource
)


def create_sample_data():
    """
    Create sample data for testing and demonstration
    """
    print("Creating sample data...")
    
    with db_manager.session_scope() as session:
        
        # Sample Threat Indicators
        indicators = [
            {
                "indicator_type": IndicatorType.IP,
                "indicator_value": "192.0.2.100",
                "threat_score": 85.5,
                "risk_level": RiskLevel.HIGH,
                "is_malicious": True,
                "primary_category": ThreatCategory.BOTNET,
                "categories": ["botnet", "malware"],
                "feed_hits": 3,
                "confidence_score": 0.92,
                "first_seen": datetime.utcnow() - timedelta(days=5),
                "last_seen": datetime.utcnow()
            },
            {
                "indicator_type": IndicatorType.DOMAIN,
                "indicator_value": "evil-phishing-site.com",
                "threat_score": 95.0,
                "risk_level": RiskLevel.CRITICAL,
                "is_malicious": True,
                "primary_category": ThreatCategory.PHISHING,
                "categories": ["phishing", "malware"],
                "feed_hits": 2,
                "confidence_score": 0.98,
                "first_seen": datetime.utcnow() - timedelta(days=2),
                "last_seen": datetime.utcnow()
            },
            {
                "indicator_type": IndicatorType.IP,
                "indicator_value": "8.8.8.8",
                "threat_score": 5.0,
                "risk_level": RiskLevel.SAFE,
                "is_malicious": False,
                "primary_category": ThreatCategory.UNKNOWN,
                "categories": [],
                "feed_hits": 0,
                "confidence_score": 0.05,
                "first_seen": datetime.utcnow() - timedelta(days=30),
                "last_seen": datetime.utcnow()
            },
            {
                "indicator_type": IndicatorType.IP,
                "indicator_value": "198.51.100.25",
                "threat_score": 65.0,
                "risk_level": RiskLevel.MEDIUM,
                "is_malicious": True,
                "primary_category": ThreatCategory.SCANNING,
                "categories": ["scanning", "brute_force"],
                "feed_hits": 2,
                "confidence_score": 0.75,
                "first_seen": datetime.utcnow() - timedelta(days=10),
                "last_seen": datetime.utcnow() - timedelta(days=1)
            }
        ]
        
        created_indicators = []
        for ind_data in indicators:
            indicator = ThreatIndicator(**ind_data)
            session.add(indicator)
            session.flush()
            created_indicators.append(indicator)
        
        print(f"  ✓ Created {len(created_indicators)} threat indicators")
        
        # Sample Feed Data
        for indicator in created_indicators[:2]:  # First 2 indicators
            feed_data = [
                FeedData(
                    indicator_id=indicator.id,
                    feed_source=FeedSource.VIRUSTOTAL,
                    feed_timestamp=datetime.utcnow(),
                    is_malicious=True,
                    reputation_score=85.0,
                    detection_count=45,
                    total_engines=70,
                    raw_response={"sample": "data", "detections": 45}
                ),
                FeedData(
                    indicator_id=indicator.id,
                    feed_source=FeedSource.ABUSEIPDB,
                    feed_timestamp=datetime.utcnow(),
                    is_malicious=True,
                    reputation_score=88.0,
                    detection_count=120,
                    total_engines=None,
                    raw_response={"abuseConfidenceScore": 88, "totalReports": 120}
                )
            ]
            session.add_all(feed_data)
        
        print(f"  ✓ Created feed data entries")
        
        # Sample Enrichment Data
        for indicator in created_indicators:
            if indicator.indicator_type == IndicatorType.IP:
                enrichment = EnrichmentData(
                    indicator_id=indicator.id,
                    geo_country="United States" if "8.8.8.8" in indicator.indicator_value else "Russia",
                    geo_country_code="US" if "8.8.8.8" in indicator.indicator_value else "RU",
                    geo_city="Mountain View" if "8.8.8.8" in indicator.indicator_value else "Moscow",
                    geo_latitude=37.4056 if "8.8.8.8" in indicator.indicator_value else 55.7558,
                    geo_longitude=-122.0775 if "8.8.8.8" in indicator.indicator_value else 37.6173,
                    asn_number=15169 if "8.8.8.8" in indicator.indicator_value else 12345,
                    asn_name="GOOGLE" if "8.8.8.8" in indicator.indicator_value else "MALICIOUS-ASN",
                    asn_organization="Google LLC" if "8.8.8.8" in indicator.indicator_value else "Unknown Hosting",
                    isp_name="Google" if "8.8.8.8" in indicator.indicator_value else "Bulletproof Hosting"
                )
            else:
                enrichment = EnrichmentData(
                    indicator_id=indicator.id,
                    whois_registrar="NameCheap Inc.",
                    whois_creation_date=datetime.utcnow() - timedelta(days=30),
                    domain_age_days=30,
                    geo_country="Panama",
                    geo_country_code="PA"
                )
            session.add(enrichment)
        
        print(f"  ✓ Created enrichment data")
        
        # Sample ML Predictions
        for indicator in created_indicators:
            prediction = MLPrediction(
                indicator_id=indicator.id,
                model_name="RandomForest_v1",
                model_version="1.0.0",
                predicted_class="malicious" if indicator.is_malicious else "safe",
                confidence=indicator.confidence_score,
                probability_safe=0.05 if indicator.is_malicious else 0.95,
                probability_suspicious=0.10 if indicator.is_malicious else 0.04,
                probability_malicious=0.85 if indicator.is_malicious else 0.01,
                is_anomaly=indicator.threat_score > 80,
                anomaly_score=indicator.threat_score / 100.0,
                feature_importance={
                    "feed_hits": 0.35,
                    "domain_age": 0.25,
                    "geo_location": 0.20,
                    "asn_reputation": 0.20
                }
            )
            session.add(prediction)
        
        print(f"  ✓ Created ML predictions")
        
        # Sample Alerts
        for indicator in created_indicators:
            if indicator.threat_score > 80:
                alert = Alert(
                    indicator_id=indicator.id,
                    severity=indicator.risk_level,
                    title=f"High-Risk {indicator.indicator_type.value.upper()} Detected",
                    description=f"Threat indicator {indicator.indicator_value} has a risk score of {indicator.threat_score}",
                    triggered_by="threshold_exceeded",
                    trigger_value=indicator.threat_score,
                    threshold=80.0,
                    is_acknowledged=False,
                    notification_sent=True,
                    notification_channels=["email", "slack"],
                    notification_timestamp=datetime.utcnow()
                )
                session.add(alert)
        
        print(f"  ✓ Created alerts")
        
        # Sample User Activity
        activities = [
            UserActivity(
                user_id="user_001",
                username="admin",
                user_ip="10.0.0.1",
                activity_type="search",
                activity_description="Searched for malicious indicators",
                resource_type="indicator",
                http_method="GET",
                endpoint="/api/indicators/search",
                response_status=200
            ),
            UserActivity(
                user_id="user_002",
                username="analyst",
                user_ip="10.0.0.2",
                activity_type="alert_acknowledge",
                activity_description="Acknowledged high-risk alert",
                resource_type="alert",
                resource_id=1,
                http_method="PUT",
                endpoint="/api/alerts/1/acknowledge",
                response_status=200
            )
        ]
        session.add_all(activities)
        
        print(f"  ✓ Created user activity logs")
        
        # Sample Scan Job
        scan_job = ScanJob(
            job_type="feed_sync",
            job_status="completed",
            feed_source=FeedSource.VIRUSTOTAL,
            indicators_processed=150,
            indicators_total=150,
            new_threats_found=12,
            alerts_triggered=3,
            errors_count=0,
            started_at=datetime.utcnow() - timedelta(minutes=10),
            completed_at=datetime.utcnow(),
            duration_seconds=600
        )
        session.add(scan_job)
        
        print(f"  ✓ Created scan job record")
        
        # Sample Report
        report = Report(
            report_type="daily",
            report_format="pdf",
            title="Daily Threat Intelligence Report",
            description="Summary of threats detected in the last 24 hours",
            date_from=datetime.utcnow() - timedelta(days=1),
            date_to=datetime.utcnow(),
            total_indicators=150,
            malicious_count=25,
            alerts_count=5,
            file_path="data/reports/daily_report_2025_11_04.pdf",
            file_size_bytes=524288,
            generated_by="admin",
            is_public=False
        )
        session.add(report)
        
        print(f"  ✓ Created report record")
        
        # System Configuration
        configs = [
            SystemConfig(
                config_key="alert_threshold",
                config_value={"value": 80},
                config_type="integer",
                description="Threat score threshold for triggering alerts",
                is_sensitive=False
            ),
            SystemConfig(
                config_key="feed_sync_interval",
                config_value={"minutes": 60},
                config_type="integer",
                description="Interval for syncing threat feeds (minutes)",
                is_sensitive=False
            ),
            SystemConfig(
                config_key="ml_model_version",
                config_value={"version": "1.0.0"},
                config_type="string",
                description="Current ML model version in use",
                is_sensitive=False
            )
        ]
        session.add_all(configs)
        
        print(f"  ✓ Created system configuration")
        
        session.commit()
    
    print("\n✅ Sample data created successfully!")


def show_statistics():
    """Display database statistics"""
    print("\n" + "="*60)
    print("📊 Database Statistics")
    print("="*60)
    
    with db_manager.session_scope() as session:
        stats = {
            "Threat Indicators": session.query(ThreatIndicator).count(),
            "Feed Data Entries": session.query(FeedData).count(),
            "Enrichment Records": session.query(EnrichmentData).count(),
            "ML Predictions": session.query(MLPrediction).count(),
            "Alerts": session.query(Alert).count(),
            "User Activities": session.query(UserActivity).count(),
            "Scan Jobs": session.query(ScanJob).count(),
            "Reports": session.query(Report).count(),
            "System Configs": session.query(SystemConfig).count()
        }
        
        for name, count in stats.items():
            print(f"  {name:.<50} {count}")
    
    print("="*60)


def main():
    """Main initialization function"""
    print("\n" + "="*60)
    print("🛡️  ThreatEye Database Initialization")
    print("="*60 + "\n")
    
    # Ask user what to do
    print("Choose an option:")
    print("  1. Initialize database (create tables)")
    print("  2. Reset database (drop and recreate all tables)")
    print("  3. Initialize with sample data")
    print("  4. Show database statistics")
    print("  5. Exit")
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    if choice == "1":
        print("\nInitializing database...")
        init_database()
        print("✅ Database initialized successfully!")
        
    elif choice == "2":
        confirm = input("\n⚠️  WARNING: This will delete ALL data! Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            reset_database()
            print("✅ Database reset complete!")
        else:
            print("❌ Reset cancelled")
            
    elif choice == "3":
        confirm = input("\n⚠️  This will reset the database and add sample data. Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            reset_database()
            create_sample_data()
            show_statistics()
        else:
            print("❌ Cancelled")
            
    elif choice == "4":
        show_statistics()
        
    elif choice == "5":
        print("Exiting...")
        
    else:
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()
