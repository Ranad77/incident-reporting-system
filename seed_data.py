from app import app, db, User, Incident
from werkzeug.security import generate_password_hash
import datetime
import random

# Sample data
student_names = [
    "Khalid AlShammari", "Ahmed AlShehri", "Fatima AlQahtani", "Mohammed AlOtaibi",
    "Sarah AlGhamdi", "Abdullah Al-Mutairi", "Noura AlDosari", "Khalid AlHarbi",
    "Layla AlZahrani", "Omar AlMalki", "Huda Al-Rasheed", "Faisal AlAnzi",
    "Maha AlShammari", "Yousef AlSaleh", "Aisha AlTamimi", "Sultan AlQaisi",
    "Reem AlJuhani", "Saud AlSubhi", "Nora AlBalawi", "Hamza AlFarsi"
]

staff_names = [
    "Dr. Nadia Almonasy", "Prof. Saeed Aldossary", "Dr. Zahida preveen",
    "Dr. Abeer AlShammari", "Dr. Tariq AlMansour"
]

incident_types = [
    "Phishing Email", "Suspicious USB Device", "Account Breach", 
    "Malware Detection", "Data Leak", "Unauthorized Access", 
    "Social Engineering", "Other"
]

descriptions = [
    "Received suspicious email claiming to be from IT department requesting password reset",
    "Found USB drive in parking lot labeled 'Salary Information - Confidential'",
    "Multiple failed login attempts detected on my university account",
    "Antivirus detected trojan malware after downloading research paper from unknown source",
    "Student records appeared to be leaked on social media platform",
    "Unauthorized person observed in server room without proper credentials",
    "Received phone call from person claiming to be university admin asking for verification code",
    "Suspicious activity detected on university network during off-hours",
    "Email attachment contained macro-enabled document requesting to enable editing",
    "Database backup files found accessible without authentication",
    "Ransomware warning message displayed on laboratory computer",
    "Student got sent an External email containing unknown attachment",
    "Fake university portal website discovered mimicking login page",
    "Suspicious network traffic detected from compromised device",
    "Security camera footage shows unauthorized access to restricted area",
    "Keylogger software discovered on public computer in library",
    "Phishing attempt via SMS pretending to be university emergency alert",
    "Confidential research data accidentally shared in public folder",
    "Former employee still has active access to internal systems",
    "Weak password policy allowed brute force attack to succeed"
]

locations = [
    "Computer Lab - Building CL1", "Library", "Engineering Department",
    "Student Center", "IT Department Office", "Main Campus Gate", "Conference Hall",
    "Science Laboratory", "Administration Building", "Parking Lot gate 7", "Building 17D",
    "Computer Science Department", "Building 17F", "Server Room", "Cafeteria",
    "Sports Complex", "Medical Center", "Student Lounge", "Building 17C"
]

severities = ["low", "medium", "high", "critical"]
statuses = ["Submitted", "Under Review", "Investigating", "Resolved", "Closed"]

def seed_database():
    with app.app_context():
        # Clear existing data
        print("🗑️ Clearing existing data...")
        db.drop_all()
        db.create_all()
        
        # Create Admin
        print("👤 Creating admin account...")
        admin = User(
            name="Admin User",
            email="admin@uoh.edu.sa",
            password=generate_password_hash("admin123"),
            role="admin",
            department="Cybersecurity Division"
        )
        db.session.add(admin)
        
        # Create Staff
        print("👥 Creating staff accounts...")
        staff_users = []
        for i, name in enumerate(staff_names):
            email = f"staff{i+1}@uoh.edu.sa"
            staff = User(
                name=name,
                email=email,
                password=generate_password_hash("staff123"),
                role="staff",
                department=random.choice(["IT Department", "Cybersecurity Division", "Network Operations"])
            )
            db.session.add(staff)
            staff_users.append(staff)
        
        # Create Students
        print("🎓 Creating student accounts...")
        student_users = []
        for i, name in enumerate(student_names):
            student_id = f"20210{3600 + i}"
            email = f"s{student_id}@uoh.edu.sa"
            student = User(
                name=name,
                email=email,
                password=generate_password_hash("student123"),
                role="student",
                student_id=student_id,
                department=random.choice([
                    "Computer Science", "Information Technology", "Engineering",
                    "Business Administration", "Medicine", "Law"
                ])
            )
            db.session.add(student)
            student_users.append(student)
        
        db.session.commit()
        print(f"✅ Created {len(student_users)} students, {len(staff_users)} staff, and 1 admin")
        
        # Create 30 Incident Reports
        print("📝 Creating 30 incident reports...")
        all_users = student_users + staff_users
        
        for i in range(30):
            reporter = random.choice(all_users)
            incident_type = random.choice(incident_types)
            
            # Create realistic timestamps (last 60 days)
            days_ago = random.randint(0, 60)
            hours_ago = random.randint(0, 23)
            created_time = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago, hours=hours_ago)
            
            incident = Incident(
                reported_by=reporter.id,
                incident_type=incident_type,
                description=random.choice(descriptions),
                location=random.choice(locations),
                incident_datetime=created_time,
                severity=random.choice(severities),
                status=random.choice(statuses),
                created_at=created_time,
                updated_at=created_time + datetime.timedelta(hours=random.randint(1, 48))
            )
            db.session.add(incident)
        
        db.session.commit()
        print("Created 30 incident reports")
        
        # Print summary
        print("\n" + "="*50)
        print("🎉 DATABASE SEEDED SUCCESSFULLY!")
        print("="*50)
        print("\n📊 SUMMARY:")
        print(f"   👤 Admin: 1 account")
        print(f"   👥 Staff: {len(staff_users)} accounts")
        print(f"   🎓 Students: {len(student_users)} accounts")
        print(f"   📝 Incidents: 30 reports")
        print("\n🔑 LOGIN CREDENTIALS:")
        print("   Admin:   admin@uoh.edu.sa / admin123")
        print("   Staff:   staff1@uoh.edu.sa / staff123")
        print("   Student: s202103600@uoh.edu.sa / student123")
        print("\n🌐 Access: http://localhost:5000")
        print("="*50 + "\n")

if __name__ == "__main__":
    seed_database()