from flask import Blueprint, Response, abort, app, render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from models import db, Link, PolicyDocument, User, ScanResult
from csrf_protection import csrf_protect
from functools import wraps

admin_bp = Blueprint('admin', __name__)

# Custom admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin Dashboard
@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_scans = ScanResult.query.count()
    malicious_scans = ScanResult.query.filter_by(status='malicious').count()
    return render_template('admin_dashboard.html',
                           total_users=total_users,
                           total_scans=total_scans,
                           malicious_scans=malicious_scans)

# Social/Partner Links Management
@admin_bp.route('/links')
@admin_required
def manage_links():
    social_links = Link.query.filter_by(type='social').all()
    partner_links = Link.query.filter_by(type='partner').all()
    return render_template('manage_links.html',
                           social_links=social_links,
                           partner_links=partner_links)

# admin_routes.py
@admin_bp.route('/link/<link_id>/toggle', methods=['POST'])
@admin_required
@csrf_protect 
def toggle_link(link_id):
    link = Link.query.get_or_404(link_id)
    link.is_visible = not link.is_visible
    db.session.commit()
    return jsonify({
        'success': True,
        'is_visible': link.is_visible
    })

# Policy Editor
@admin_bp.route('/edit-policy/<doc_type>', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def edit_policy(doc_type):
    # Validate document type
    if doc_type not in ['tos', 'privacy']:
        abort(404)
    
    document = PolicyDocument.query.filter_by(document_type=doc_type).first()
    
    if request.method == 'POST':
        # Ensure doc_type matches the route parameter
        post_doc_type = request.form.get('doc_type')
        if post_doc_type != doc_type:
            abort(400, "Document type mismatch")
            
        # Rest of your existing save logic
        if not document:
            document = PolicyDocument(document_type=doc_type)
            db.session.add(document)
        
        document.content = request.form['content']
        db.session.commit()
        return redirect(url_for('admin.edit_policy', doc_type=doc_type))

    return render_template('edit_policy.html', document=document, doc_type=doc_type)

# User Management
@admin_bp.route('/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('user_management.html', users=users)

@admin_bp.route('/export/users.csv')
@admin_required
def export_users_csv():
    users = User.query.all()
    csv_data = "Email,Registration Date,Last Login\n"
    for user in users:
        csv_data += f"{user.email},{user.created_at},{user.last_login}\n"
    return Response(csv_data, mimetype="text/csv")

@admin_bp.route('/chart-data')
def get_chart_data():
    total_scans = ScanResult.query.count()

    malicious_scans = ScanResult.query.filter(
        ScanResult.status == 'Reported'
    ).count()

    safe_scans = total_scans - malicious_scans

    return jsonify({
        'total_scans': total_scans,
        'malicious_scans': malicious_scans,
        'safe_scans': safe_scans
    })

@admin_bp.route('/links', methods=['POST'])
@admin_required 
@csrf_protect
def handle_links():
    try:
        if request.method == 'POST':
            new_link = Link(
                name=request.form['name'],
                url=request.form['url'],
                type=request.form['type'],
                is_visible=True
            )
            db.session.add(new_link)
            db.session.commit()
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@admin_bp.route('/link/<link_id>/delete', methods=['DELETE'])
@admin_required
@csrf_protect
def delete_link(link_id):
    link = Link.query.get_or_404(link_id)
    db.session.delete(link)
    db.session.commit()
    return jsonify({'success': True})