import os
import csv
import json
import random
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import List, Dict, Optional, Any

from flask import Flask, request, jsonify, g, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from tinydb import TinyDB, Query
from tinydb.middlewares import CachingMiddleware
from tinydb.storages import JSONStorage
import logging
from logging.handlers import RotatingFileHandler

# -------------------------
# Basic app + config
# -------------------------
# Initialize Flask app without static route
app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Make JSON responses preserve unicode characters
# (Flask >= 2.2 uses app.json but we explicitly control response serialization below)
# -------------------------
# Rate limiting
# -------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"],
    storage_uri="memory://"
)

# -------------------------
# TinyDB setup (with caching)
# -------------------------
DB_PATH = os.environ.get('TINYDB_PATH', 'quotes.json')
db = TinyDB(DB_PATH, storage=CachingMiddleware(JSONStorage))
quotes_table = db.table('quotes')
api_keys_table = db.table('api_keys')
logs_table = db.table('api_logs')

# -------------------------
# Logging
# -------------------------
def setup_logging():
    """Setup comprehensive logging with rotation and UTF-8 encoding."""
    # ensure logs dir exists
    os.makedirs('logs', exist_ok=True)

    file_handler = RotatingFileHandler(
        'logs/quotes_api.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding='utf-8'  # important for Devanagari text in logs
    )

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # if running with debug True, keep INFO anyway for file logging
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Hindi Quotes API startup')

setup_logging()

# -------------------------
# Utilities
# -------------------------
def iso_now() -> str:
    return datetime.utcnow().isoformat() + 'Z'

# -------------------------
# API Key management
# -------------------------
class APIKeyManager:
    @staticmethod
    def generate_api_key(name: str = "default") -> str:
        """Generate and store a new API key (store hash only)."""
        api_key = f"hq_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_keys_table.insert({
            'id': str(uuid.uuid4()),
            'name': name,
            'key_hash': key_hash,
            'created_at': iso_now(),
            'is_active': True,
            'usage_count': 0
        })
        return api_key

    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """Validate API key and update usage count atomically-ish."""
        if not api_key or not api_key.startswith('hq_'):
            return False

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        q = Query()
        key_record = api_keys_table.get((q.key_hash == key_hash) & (q.is_active == True))

        if key_record:
            # increment usage_count
            api_keys_table.update({'usage_count': key_record.get('usage_count', 0) + 1},
                                  q.key_hash == key_hash)
            return True

        return False

# -------------------------
# Auth decorator
# -------------------------
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = (
            request.headers.get('X-API-Key') or
            (request.headers.get('Authorization') or '').replace('Bearer ', '') or
            request.args.get('api_key')
        )
        if not APIKeyManager.validate_api_key(api_key):
            log_api_request(
                endpoint=request.endpoint or 'unknown',
                method=request.method,
                status_code=401,
                error="Invalid API key"
            )
            return create_response({'error': 'Invalid or missing API key'}, status=401)
        g.api_key = api_key
        return f(*args, **kwargs)
    return decorated_function

# -------------------------
# Logging helper (stores structured logs in TinyDB)
# -------------------------
def log_api_request(endpoint: str, method: str, status_code: int,
                    params: Dict = None, error: str = None):
    """Write structured log entry to tinydb and app logger."""
    try:
        entry = {
            'id': str(uuid.uuid4()),
            'timestamp': iso_now(),
            'endpoint': endpoint,
            'method': method,
            'status_code': int(status_code),
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent', '') if request else '',
            'params': params or {},
            'error': error
        }
        logs_table.insert(entry)

        # Log a short line to rotating file
        app.logger.info(f"{method} {endpoint} - {status_code} - {entry['ip_address']}")
    except Exception as e:
        # Ensure logging errors don't crash the app
        app.logger.exception("Failed to write log entry: %s", e)

# -------------------------
# Quote management
# -------------------------
class QuoteManager:
    VALID_TYPES = ['success', 'sad', 'motivational', 'love', 'attitude', 'positive']

    @staticmethod
    def import_from_csv(file_path: str) -> int:
        """Import quotes from CSV file (expects header: type,quote)"""
        imported_count = 0
        if not os.path.exists(file_path):
            return 0

        with open(file_path, 'r', encoding='utf-8') as csvfile:
            # use DictReader, expect headers 'type' and 'quote'
            reader = csv.DictReader(csvfile)
            for row in reader:
                if not row:
                    continue
                quote_type = (row.get('type') or '').strip().lower()
                quote_text = (row.get('quote') or '').strip()
                if not quote_type or not quote_text:
                    continue
                if quote_type not in QuoteManager.VALID_TYPES:
                    # normalize unknown types to 'motivational' (or skip) — here we skip
                    continue

                # check duplicate by exact quote text
                q = Query()
                existing = quotes_table.get(q.quote == quote_text)
                if existing:
                    continue

                record = {
                    'id': str(uuid.uuid4()),
                    'type': quote_type,
                    'quote': quote_text,
                    'created_at': iso_now()
                }
                quotes_table.insert(record)
                imported_count += 1

        app.logger.info(f"Imported {imported_count} quotes from {file_path}")
        return imported_count

    @staticmethod
    def get_quotes_by_type(quote_type: str, limit: int = None) -> List[Dict]:
        q = Query()
        results = quotes_table.search(q.type == quote_type.lower())
        if limit is not None:
            results = results[:limit]
        return results

    @staticmethod
    def get_random_quote(quote_type: str = None) -> Optional[Dict]:
        if quote_type:
            quotes = QuoteManager.get_quotes_by_type(quote_type)
        else:
            quotes = quotes_table.all()
        return random.choice(quotes) if quotes else None

    @staticmethod
    def get_all_quotes(limit: int = None) -> List[Dict]:
        quotes = quotes_table.all()
        if limit is not None:
            quotes = quotes[:limit]
        return quotes

# -------------------------
# Response helper (ensures utf-8 and non-ascii escaping)
# -------------------------
def create_response(data: Any = None, message: str = None, status: int = 200,
                    quote_type: str = None) -> Response:
    """Return a consistent JSON response with utf-8 encoding and no ascii escaping."""
    payload: Dict[str, Any] = {}
    if message:
        payload['message'] = message

    if data is not None:
        if isinstance(data, list):
            payload['quotes'] = data
            payload['count'] = len(data)
        else:
            payload['quote'] = data

    if quote_type:
        payload['type'] = quote_type

    payload['timestamp'] = iso_now()

    json_str = json.dumps(payload, ensure_ascii=False)
    return app.response_class(json_str, mimetype='application/json; charset=utf-8'), status

# -------------------------
# Routes
# -------------------------
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'Hindi Quotes API - Fixed Version',
        'version': '2.1.0',
        'description': 'A simple REST API for Hindi motivational quotes (UTF-8 / Devanagari safe)',
        'quote_types': QuoteManager.VALID_TYPES,
        'endpoints': {
            'GET /': 'API information',
            'GET /quotes': 'Get all quotes (requires API key)',
            'GET /quotes/random': 'Get a random quote (any type) (requires API key)',
            'GET /quotes/random?type=TYPE': 'Get random quote of specific type (requires API key)',
            'GET /<type>/random': 'Type-specific random quote endpoints',
            'GET /stats': 'Get API statistics (requires API key)'
        },
        'authentication': {
            'methods': [
                'Header: X-API-Key: your_key',
                'Header: Authorization: Bearer your_key',
                'Query: ?api_key=your_key'
            ],
            'note': 'Header method (X-API-Key) is recommended'
        }
    })

@app.route('/quotes', methods=['GET'])
@require_api_key
@limiter.limit("100 per minute")
def get_quotes():
    try:
        limit = request.args.get('limit', type=int)
        quotes = QuoteManager.get_all_quotes(limit)
        log_api_request('get_quotes', 'GET', 200, {'limit': limit, 'count': len(quotes)})
        return create_response(quotes, quote_type='all')
    except Exception as e:
        app.logger.exception("get_quotes failed")
        log_api_request('get_quotes', 'GET', 500, error=str(e))
        return create_response({'error': 'Internal server error'}, status=500)

@app.route('/quotes/random', methods=['GET'])
@require_api_key
@limiter.limit("200 per minute")
def get_random_quote():
    try:
        quote_type = (request.args.get('type') or '').strip().lower()
        if quote_type and quote_type not in QuoteManager.VALID_TYPES:
            log_api_request('get_random_quote', 'GET', 400, {'type': quote_type}, 'Invalid quote type')
            return create_response({'error': f'Invalid quote type. Valid types: {", ".join(QuoteManager.VALID_TYPES)}'}, status=400)

        quote = QuoteManager.get_random_quote(quote_type if quote_type else None)
        if not quote:
            log_api_request('get_random_quote', 'GET', 404, {'type': quote_type}, 'No quotes found')
            return create_response({'error': 'No quotes found'}, status=404)

        log_api_request('get_random_quote', 'GET', 200, {'type': quote_type})
        return create_response(quote, quote_type=quote_type or 'random')
    except Exception as e:
        app.logger.exception("get_random_quote failed")
        log_api_request('get_random_quote', 'GET', 500, error=str(e))
        return create_response({'error': 'Internal server error'}, status=500)

# generic type-specific endpoint (less repetitive)
@app.route('/<quote_type>/random', methods=['GET'])
@require_api_key
@limiter.limit("200 per minute")
def get_random_by_type(quote_type):
    quote_type_norm = (quote_type or '').strip().lower()
    if quote_type_norm not in QuoteManager.VALID_TYPES:
        log_api_request('get_random_by_type', 'GET', 400, {'type': quote_type_norm}, 'Invalid quote type')
        return create_response({'error': f'Invalid quote type. Valid types: {", ".join(QuoteManager.VALID_TYPES)}'}, status=400)
    try:
        quote = QuoteManager.get_random_quote(quote_type_norm)
        if not quote:
            log_api_request('get_random_by_type', 'GET', 404, {'type': quote_type_norm}, 'No quotes found')
            return create_response({'error': f'No {quote_type_norm} quotes found'}, status=404)
        log_api_request('get_random_by_type', 'GET', 200, {'type': quote_type_norm})
        return create_response(quote, quote_type=quote_type_norm)
    except Exception as e:
        app.logger.exception("get_random_by_type failed")
        log_api_request('get_random_by_type', 'GET', 500, error=str(e))
        return create_response({'error': 'Internal server error'}, status=500)

@app.route('/stats', methods=['GET'])
@require_api_key
@limiter.limit("20 per minute")
def get_stats():
    try:
        # Count quotes by type
        type_counts = {qt: len(QuoteManager.get_quotes_by_type(qt)) for qt in QuoteManager.VALID_TYPES}

        # Get recent logs (last 24 hours) — filter in Python for correctness
        cutoff = datetime.utcnow() - timedelta(days=1)
        recent_logs = []
        for entry in logs_table.all():
            ts = entry.get('timestamp')
            if not ts:
                continue
            # parse ISO format with optional trailing Z
            try:
                parsed = datetime.fromisoformat(ts.replace('Z', ''))
            except Exception:
                continue
            if parsed >= cutoff:
                recent_logs.append(entry)

        total_requests = len(recent_logs)
        successful_requests = len([l for l in recent_logs if int(l.get('status_code', 0)) < 400])
        error_requests = total_requests - successful_requests

        # Most popular endpoints
        endpoint_counts = {}
        for log in recent_logs:
            endpoint = log.get('endpoint') or 'unknown'
            endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

        popular_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        stats = {
            'total_quotes': len(quotes_table),
            'quotes_by_type': type_counts,
            'api_stats_24h': {
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'error_requests': error_requests,
                'success_rate': f"{(successful_requests/total_requests*100):.1f}%" if total_requests > 0 else "0%"
            },
            'popular_endpoints_24h': [{'endpoint': ep, 'requests': count} for ep, count in popular_endpoints],
            'valid_quote_types': QuoteManager.VALID_TYPES,
            'available_endpoints': len([rule for rule in app.url_map.iter_rules()]),
            'timestamp': iso_now()
        }

        log_api_request('get_stats', 'GET', 200)
        json_str = json.dumps(stats, ensure_ascii=False, indent=2)
        return app.response_class(json_str, mimetype='application/json; charset=utf-8')
    except Exception as e:
        app.logger.exception("get_stats failed")
        log_api_request('get_stats', 'GET', 500, error=str(e))
        return create_response({'error': 'Internal server error'}, status=500)

# -------------------------
# Error handlers
# -------------------------
@app.errorhandler(404)
def not_found(error):
    return create_response({'error': 'Endpoint not found', 'available_endpoints': 'Visit / for complete endpoint list'}, status=404)

@app.errorhandler(429)
def ratelimit_handler(error):
    log_api_request(request.endpoint or 'unknown', request.method or 'GET', 429, error='Rate limit exceeded')
    return create_response({'error': 'Rate limit exceeded. Please try again later.', 'retry_after': getattr(error, 'retry_after', 60)}, status=429)

@app.errorhandler(500)
def internal_error(error):
    log_api_request(request.endpoint or 'unknown', request.method or 'GET', 500, error='Internal server error')
    return create_response({'error': 'Internal server error'}, status=500)

# -------------------------
# Initialization routine
# -------------------------
def initialize_app():
    """Initialize the application with sample data and API key"""
    print("🚀 Initializing Hindi Quotes API - Fixed Version...")
    print("-" * 70)

    # Create initial API key if none exists
    if not api_keys_table.all():
        api_key = APIKeyManager.generate_api_key("initial_key")
        print(f"✅ Created initial API key: {api_key}")
        print("🔐 SAVE THIS KEY SECURELY - it won't be shown again!")
        print("")
        print("📋 Authentication Methods:")
        print(f"   • Header: X-API-Key: {api_key}")
        print(f"   • Header: Authorization: Bearer {api_key}")
        print(f"   • Query: ?api_key={api_key}")
        print("-" * 70)
    else:
        print("✅ API keys already exist in database")

    # Try to import CSV files (prefer hindiquotes.csv)
    csv_files = ['hindiquotes.csv', 'quotes.csv', 'quotes.csv']
    for csv_file in csv_files:
        if os.path.exists(csv_file):
            try:
                # If you want to avoid duplicates across restarts, consider truncating explicitly
                imported = QuoteManager.import_from_csv(csv_file)
                print(f"📚 Imported {imported} quotes from {csv_file}")
                break
            except Exception as e:
                print(f"❌ Error importing {csv_file}: {e}")

    quote_count = len(quotes_table.all())
    if quote_count > 0:
        type_breakdown = {}
        for qtype in QuoteManager.VALID_TYPES:
            count = len(QuoteManager.get_quotes_by_type(qtype))
            if count > 0:
                type_breakdown[qtype] = count
        print(f"Database contains {quote_count} quotes:")
        for qtype, count in type_breakdown.items():
            print(f"   • {qtype}: {count} quotes")
    else:
        print("📝 No quotes found - place hindiquotes.csv or quotes.csv in the same directory (UTF-8 encoded).")

    print("")
    print("API Endpoints:")
    for rule in sorted([str(r) for r in app.url_map.iter_rules()]):
        print("   •", rule)
    print("")
    print("API is ready to serve requests!")
    print("-" * 70)

# -------------------------
# Shutdown hook to persist TinyDB cache (optional)
# -------------------------
@app.teardown_appcontext
def close_db(exception=None):
    try:
        # flush caching middleware to disk
        db.close()
    except Exception:
        pass

# -------------------------
# Run
# -------------------------
if __name__ == '__main__':
    initialize_app()

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    host = os.environ.get('HOST', '0.0.0.0')

    print(f"🌐 Starting Hindi Quotes API on {host}:{port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"📊 Visit http://{host}:{port}/ for complete API documentation")
    print("-" * 70)

    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )
