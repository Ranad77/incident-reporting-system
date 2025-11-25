from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
import json
from functools import wraps

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)

# Configuration
app.config['SECRET_KEY'] = 'uoh-incident-reporting-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incident_reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize
db = SQLAlchemy(app)
# Allow CORS for API calls from any origin (fine for testing; lock down for production)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')
    student_id = db.Column(db.String(20))
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    incident_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200))
    incident_datetime = db.Column(db.DateTime)
    severity = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(50), default='Submitted')
    images = db.Column(db.Text)  # store images as JSON string
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    reporter = db.relationship('User', backref='incidents')


# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401

        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'success': False, 'message': 'User not found'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': 'Token is invalid', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# ---------- Page routes (render templates) ----------
# Serve the login page at root
@app.route('/')
def index():
    return render_template('login.html')

# Explicit routes for each HTML template you have
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/my-reports')
def my_reports_page():
    return render_template('my-reports.html')

@app.route('/report-incident')
def report_incident_page():
    return render_template('report-incident.html')

@app.route('/admin-panel')
def admin_panel_page():
    return render_template('admin-panel.html')

@app.route('/view-report')
def view_report_page():
    return render_template('view-report.html')


# Serve static files (CSS/JS/images)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# Password validation function
def validate_password(password):
    import re
    if len(password) < 8:
        return 'Password must be at least 8 characters long'
    if not re.search(r'[A-Z]', password):
        return 'Password must include at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return 'Password must include at least one lowercase letter'
    if not re.search(r'[!@#$%^&*_\-+=?]', password):
        return 'Password must include at least one special character (!@#$%^&*_-+=?)'
    return None


# ---------- Auth Routes (API) ----------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'message': 'No input data provided'}), 400

    # Check if user exists
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'message': 'User already exists'}), 400

    # Validate password strength
    password_error = validate_password(data.get('password', ''))
    if password_error:
        return jsonify({'success': False, 'message': password_error}), 400

    # Create user
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        name=data.get('name'),
        email=data.get('email'),
        password=hashed_password,
        role=data.get('role', 'student'),
        student_id=data.get('studentId'),
        department=data.get('department')
    )

    db.session.add(new_user)
    db.session.commit()

    # Generate token
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'success': True,
        'message': 'User registered successfully',
        'token': token,
        'user': {
            'id': new_user.id,
            'name': new_user.name,
            'email': new_user.email,
            'role': new_user.role
        }
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No input data provided'}), 400

    user = User.query.filter_by(email=data.get('email')).first()

    if not user or not check_password_hash(user.password, data.get('password', '')):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    if not user.is_active:
        return jsonify({'success': False, 'message': 'Account is deactivated'}), 403

    # Generate token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department
        }
    })


# ---------- Incident API ----------
@app.route('/api/incidents', methods=['GET'])
@token_required
def get_incidents(current_user):
    incidents = Incident.query.all()

    result = []
    for incident in incidents:
        result.append({
            '_id': str(incident.id),
            'incidentType': incident.incident_type,
            'description': incident.description,
            'location': incident.location,
            'severity': incident.severity,
            'status': incident.status,
            'images': json.loads(incident.images) if incident.images else [],
            'createdAt': incident.created_at.isoformat(),
            'reportedBy': {
                '_id': str(incident.reporter.id),
                'name': incident.reporter.name,
                'email': incident.reporter.email,
                'role': incident.reporter.role
            }
        })

    return jsonify({'success': True, 'data': result})


@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
@token_required
def get_incident(current_user, incident_id):
    incident = Incident.query.get(incident_id)

    if not incident:
        return jsonify({'success': False, 'message': 'Incident not found'}), 404

    result = {
        '_id': str(incident.id),
        'incidentType': incident.incident_type,
        'description': incident.description,
        'location': incident.location,
        'incidentDateTime': incident.incident_datetime.isoformat() if incident.incident_datetime else None,
        'severity': incident.severity,
        'status': incident.status,
        'images': json.loads(incident.images) if incident.images else [],
        'createdAt': incident.created_at.isoformat(),
        'updatedAt': incident.updated_at.isoformat(),
        'reportedBy': {
            '_id': str(incident.reporter.id),
            'name': incident.reporter.name,
            'email': incident.reporter.email,
            'role': incident.reporter.role,
            'department': incident.reporter.department
        }
    }

    return jsonify({'success': True, 'data': result})


@app.route('/api/incidents', methods=['POST'])
@token_required
def create_incident(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No input data provided'}), 400

    images = data.get('images', [])
    images_json = json.dumps(images) if images else None

    new_incident = Incident(
        reported_by=current_user.id,
        incident_type=data.get('incidentType'),
        description=data.get('description'),
        location=data.get('location'),
        incident_datetime=datetime.datetime.fromisoformat(data.get('incidentDateTime', datetime.datetime.utcnow().isoformat())),
        severity=data.get('severity', 'medium'),
        status='Submitted',
        images=images_json
    )

    db.session.add(new_incident)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Incident created successfully',
        'data': {
            '_id': str(new_incident.id),
            'incidentType': new_incident.incident_type,
            'status': new_incident.status
        }
    }), 201


@app.route('/api/incidents/<int:id>', methods=['PUT'])
@token_required
def update_incident(current_user, id):
    incident = Incident.query.get(id)

    if not incident:
        return jsonify({'success': False, 'message': 'Incident not found'}), 404

    data = request.get_json()

    if 'status' in data:
        incident.status = data['status']
    if 'severity' in data:
        incident.severity = data['severity']

    incident.updated_at = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({'success': True, 'message': 'Incident updated successfully'})


@app.route('/api/incidents/<int:id>', methods=['DELETE'])
@token_required
def delete_incident(current_user, id):
    incident = Incident.query.get(id)

    if not incident:
        return jsonify({'success': False, 'message': 'Incident not found'}), 404

    db.session.delete(incident)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Incident deleted successfully'})


# Initialize database
with app.app_context():
    db.create_all()
    print("Database is initialized!")


if __name__ == '__main__':
    import os
    print("Starting Flask server...")
    port = int(os.environ.get('PORT', 5000))
    print(f"Access the system at: http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
