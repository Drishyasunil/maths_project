document.addEventListener('DOMContentLoaded', () => {
    
    // Simulate Elements
    const btnSimulate = document.getElementById('btn-simulate');
    const simResults = document.getElementById('sim-results');
    const resPlainEntropy = document.getElementById('res-plain-entropy');
    const resEncEntropy = document.getElementById('res-enc-entropy');
    const simBadge = document.getElementById('sim-badge');

    // API URL
    const API_BASE = 'http://localhost:5000/api';

    // --- Simulation ---
    if (btnSimulate) {
        btnSimulate.addEventListener('click', () => {
            btnSimulate.disabled = true;
            btnSimulate.textContent = 'Running Simulation...';
            simBadge.textContent = 'Processing';
            simBadge.className = 'badge running';

            fetch(`${API_BASE}/simulate`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        resPlainEntropy.textContent = data.results['sample_plain.txt'].entropy.toFixed(4);
                        resEncEntropy.textContent = data.results['sample_encrypted.enc'].entropy.toFixed(4);
                        
                        simResults.classList.remove('hidden');
                        simResults.style.display = 'grid';
                        simResults.style.opacity = '1';
                    }
                })
                .catch(err => {
                    console.error(err);
                    alert("Error running simulation. Check console.");
                })
                .finally(() => {
                    btnSimulate.disabled = false;
                    btnSimulate.textContent = 'Run Simulation';
                    simBadge.textContent = 'Ready';
                    simBadge.className = 'badge';
                });
        });
    }

    // --- File Upload & Analysis ---
    const btnUpload = document.getElementById('btn-upload');
    const fileInput = document.getElementById('file-input');
    const uploadBadge = document.getElementById('upload-badge');

    if (btnUpload) {
        btnUpload.addEventListener('click', () => {
            if (!fileInput.files.length) {
                alert("Please select a file first.");
                return;
            }

            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append('file', file);

            btnUpload.disabled = true;
            btnUpload.textContent = 'Analyzing...';
            uploadBadge.textContent = 'Processing';
            uploadBadge.className = 'badge running';

            fetch(`${API_BASE}/upload/analyze`, {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    const risk = data.risk_percent;
                    
                    let barColor, verdictBg, verdictColor;
                    if (risk < 20) {
                        barColor = 'var(--accent-success)';
                        verdictBg = 'rgba(16,185,129,0.15)';
                        verdictColor = 'var(--accent-success)';
                    } else if (risk < 50) {
                        barColor = '#f59e0b';
                        verdictBg = 'rgba(245,158,11,0.15)';
                        verdictColor = '#f59e0b';
                    } else if (risk < 75) {
                        barColor = '#f97316';
                        verdictBg = 'rgba(249,115,22,0.15)';
                        verdictColor = '#f97316';
                    } else {
                        barColor = 'var(--accent-danger)';
                        verdictBg = 'rgba(239,68,68,0.15)';
                        verdictColor = 'var(--accent-danger)';
                    }

                    const sizeKB = (data.size_bytes / 1024).toFixed(1);
                    const sizeStr = data.size_bytes > 1024 * 1024
                        ? `${(data.size_bytes / 1048576).toFixed(2)} MB`
                        : `${sizeKB} KB`;

                    document.getElementById('res-filename').textContent = data.filename;
                    document.getElementById('res-filetype').textContent = `Detected Type: ${data.file_type}`;
                    document.getElementById('res-entropy-val').textContent = data.entropy.toFixed(4);
                    document.getElementById('res-size-val').textContent = sizeStr;
                    document.getElementById('res-risk-pct').textContent = `${risk}%`;
                    document.getElementById('res-risk-pct').style.color = verdictColor;

                    const verdictEl = document.getElementById('res-verdict');
                    verdictEl.textContent = data.status_text;
                    verdictEl.style.background = verdictBg;
                    verdictEl.style.color = verdictColor;

                    const bar = document.getElementById('res-risk-bar');
                    bar.style.width = '0%';
                    bar.style.background = barColor;
                    setTimeout(() => { bar.style.width = `${risk}%`; }, 50);

                    const reasonsList = document.getElementById('res-reasons');
                    reasonsList.innerHTML = '';
                    data.reasons.forEach(r => {
                        const li = document.createElement('li');
                        li.style.cssText = `background: rgba(15,23,42,0.6); padding: 10px 14px; border-radius: 8px; font-size: 0.85rem; border-left: 3px solid ${barColor};`;
                        li.textContent = r;
                        reasonsList.appendChild(li);
                    });

                    const resultsEl = document.getElementById('upload-results');
                    resultsEl.classList.remove('hidden');
                    resultsEl.style.display = 'grid';
                    resultsEl.style.opacity = '1';
                } else {
                    alert(`Error: ${data.message}`);
                }
            })
            .catch(err => {
                console.error(err);
                alert("Error analyzing file. Check console.");
            })
            .finally(() => {
                btnUpload.disabled = false;
                btnUpload.textContent = 'Upload & Analyze';
                uploadBadge.textContent = 'Ready';
                uploadBadge.className = 'badge';
                fileInput.value = '';
            });
        });
    }

});
