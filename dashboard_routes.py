from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models import db,ScanResult
from datetime import datetime, timedelta
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/data', methods=['GET'])
@login_required
def get_dashboard_data():
    # Stats Query (Separate from pagination)
    stats_query = ScanResult.query.filter_by(user_id=current_user.id)
    
    stats = {
        "total_scans": stats_query.count(),
        "safe_count": stats_query.filter_by(status="Safe").count(),
        "phishing_count": stats_query.filter_by(status="malicious").count()
    }

    # Recent Scans (Paginated)
    page = int(request.args.get('page', 1))
    per_page = 5
    scans_paginated = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    scan_data = [{
        'url': scan.url,
        'status': scan.status,
        'risk_score': scan.risk_score,
        'scanned_at': scan.created_at.strftime("%Y-%m-%d %H:%M"),
    } for scan in scans_paginated.items]

    # Risk Trend Data (Last 6 months)
    risk_trend = db.session.query(
        func.strftime('%Y-%m', ScanResult.created_at).label('month'),
        func.count(ScanResult.id).filter(ScanResult.status == 'malicious').label('malicious')
    ).filter(
        ScanResult.created_at >= datetime.now() - timedelta(days=180)
    ).group_by('month').all()

    
    print("Risk Trend Data:", risk_trend)
    print("Formatted Risk Trend:", [{"month": r[0], "malicious": r[1]} for r in risk_trend])

    return jsonify({
        "stats": stats,
        "scans": scan_data,
        "risk_trend": [{"month": r[0], "malicious": r[1]} for r in risk_trend],
        "has_next": scans_paginated.has_next,
        "has_prev": scans_paginated.has_prev,
        "current_page": scans_paginated.page,
        "total_pages": scans_paginated.pages
    })