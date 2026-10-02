import os
import sys
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Add the project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from entropy_analyzer.core import calculate_shannon_entropy, analyze_file_structure
from scripts.simulate_data import generate_plaintext_file, generate_encrypted_file

app = Flask(__name__, static_folder='static')
CORS(app)

MONITOR_THRESHOLD = 7.9

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

# ─────────────────────────────────────────────────────────────
# Simulation Route
# ─────────────────────────────────────────────────────────────

@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    """Runs the simulation and returns the entropy results."""
    plain_file = "sample_plain.txt"
    enc_file = "sample_encrypted.enc"

    generate_plaintext_file(plain_file, 512 * 1024)
    generate_encrypted_file(plain_file, enc_file)

    results = {}
    for file in [plain_file, enc_file]:
        with open(file, 'rb') as f:
            data = f.read()
            entropy = calculate_shannon_entropy(data)
            results[file] = {
                "size_bytes": len(data),
                "entropy": round(entropy, 4)
            }

    return jsonify({"status": "success", "results": results})

# ─────────────────────────────────────────────────────────────
# Manual File Upload Analysis
# ─────────────────────────────────────────────────────────────

@app.route('/api/upload/analyze', methods=['POST'])
def api_upload_analyze():
    """Accepts any uploaded file and runs the full multi-factor threat analysis."""
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part in request."}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"status": "error", "message": "No file selected."}), 400

    data = uploaded_file.read()
    analysis = analyze_file_structure(data, threshold=MONITOR_THRESHOLD)

    return jsonify({
        "status": "success",
        "filename": uploaded_file.filename,
        "size_bytes": len(data),
        **analysis
    })

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("[*] Starting Web Dashboard on http://localhost:5000")
    app.run(debug=True, use_reloader=False)
