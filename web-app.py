from flask import Flask, render_template_string, request, jsonify, Response
import subprocess
import threading
import queue
import sys
from io import StringIO

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>JC Destroyer - Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e7;
            padding: 20px;
            min-height: 100vh;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto;
        }
        header {
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 { 
            color: #f4f4f5;
            font-size: 28px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }
        .subtitle {
            color: #a1a1aa;
            font-size: 14px;
            margin-top: 5px;
        }
        #terminal { 
            background: #0f172a;
            padding: 20px; 
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px; 
            height: 65vh; 
            overflow-y: auto; 
            margin-bottom: 20px;
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        #terminal::-webkit-scrollbar {
            width: 8px;
        }
        #terminal::-webkit-scrollbar-track {
            background: #1e293b;
        }
        #terminal::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 4px;
        }
        .input-group {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        input { 
            flex: 1;
            padding: 14px 16px; 
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 14px; 
            background: #0f172a;
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e4e4e7;
            border-radius: 6px;
            transition: all 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        button { 
            padding: 14px 24px; 
            background: #3b82f6;
            color: white;
            border: none; 
            cursor: pointer;
            font-weight: 500;
            font-size: 14px;
            border-radius: 6px;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2);
        }
        button:hover { 
            background: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3);
        }
        button:active {
            transform: translateY(0);
        }
        button.secondary {
            background: #64748b;
            box-shadow: 0 2px 4px rgba(100, 116, 139, 0.2);
        }
        button.secondary:hover {
            background: #475569;
            box-shadow: 0 4px 8px rgba(100, 116, 139, 0.3);
        }
        .output-line { 
            margin: 3px 0;
            padding: 2px 0;
        }
        .error { 
            color: #ef4444;
            font-weight: 500;
        }
        .success { 
            color: #10b981;
        }
        .warning { 
            color: #f59e0b;
        }
        .info {
            color: #3b82f6;
        }
        .prompt {
            color: #8b5cf6;
            font-weight: 600;
        }
        .status-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: #0f172a;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #64748b;
            animation: pulse 2s infinite;
        }
        .status-dot.active {
            background: #10b981;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>JC Destroyer Control Panel</h1>
            <div class="subtitle">Remote scanner management interface</div>
        </header>
        
        <div class="status-bar">
            <div class="status-indicator">
                <div class="status-dot" id="statusDot"></div>
                <span id="statusText">Ready</span>
            </div>
            <div id="timestamp"></div>
        </div>
        
        <div id="terminal">
            <div class="success">● System initialized and ready for commands</div>
        </div>
        
        <div class="input-group">
            <input type="text" id="command" placeholder="Enter command..." autofocus>
            <button onclick="sendCommand()">Send</button>
            <button class="secondary" onclick="startScanner()">Start Scanner</button>
        </div>
    </div>
    
    <script>
        const terminal = document.getElementById('terminal');
        const input = document.getElementById('command');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const timestamp = document.getElementById('timestamp');
        
        function updateTime() {
            const now = new Date();
            timestamp.textContent = now.toLocaleTimeString();
        }
        updateTime();
        setInterval(updateTime, 1000);
        
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendCommand();
        });
        
        function addOutput(text, className = '') {
            const line = document.createElement('div');
            line.className = 'output-line ' + className;
            line.textContent = text;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function setStatus(text, active = false) {
            statusText.textContent = text;
            if (active) {
                statusDot.classList.add('active');
            } else {
                statusDot.classList.remove('active');
            }
        }
        
        function sendCommand() {
            const cmd = input.value.trim();
            if (!cmd) return;
            
            addOutput('$ ' + cmd, 'prompt');
            input.value = '';
            
            fetch('/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            })
            .then(r => r.json())
            .then(data => {
                if (data.output) {
                    data.output.split('\\n').forEach(line => {
                        if (line.trim()) addOutput(line, 'info');
                    });
                }
            })
            .catch(err => addOutput('Error: ' + err, 'error'));
        }
        
        function startScanner() {
            addOutput('→ Initializing scanner...', 'info');
            setStatus('Starting...', true);
            
            fetch('/start', {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                addOutput('✓ ' + data.status, 'success');
                setStatus('Running', true);
            })
            .catch(err => {
                addOutput('✗ Error: ' + err, 'error');
                setStatus('Error', false);
            });
            
            pollOutput();
        }
        
        function pollOutput() {
            fetch('/output')
            .then(r => r.json())
            .then(data => {
                if (data.output) {
                    data.output.split('\\n').forEach(line => {
                        if (line.trim()) addOutput(line);
                    });
                }
                if (data.running) {
                    setTimeout(pollOutput, 1000);
                } else {
                    setStatus('Ready', false);
                }
            });
        }
    </script>
</body>
</html>
"""

process = None
output_buffer = []

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/start', methods=['POST'])
def start():
    global process, output_buffer
    output_buffer = []
    
    try:
        process = subprocess.Popen(
            ['python3', 'destroyerjc.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        def read_output():
            for line in process.stdout:
                output_buffer.append(line.strip())
        
        threading.Thread(target=read_output, daemon=True).start()
        return jsonify({'status': 'Scanner started'})
    except Exception as e:
        return jsonify({'status': f'Error: {str(e)}'})

@app.route('/execute', methods=['POST'])
def execute():
    global process
    command = request.json.get('command', '')
    
    if process and process.poll() is None:
        try:
            process.stdin.write(command + '\\n')
            process.stdin.flush()
            return jsonify({'output': f'Command sent: {command}'})
        except:
            return jsonify({'output': 'Error sending command'})
    else:
        return jsonify({'output': 'No active process. Click Start Scanner first.'})

@app.route('/output')
def get_output():
    global output_buffer, process
    output = '\\n'.join(output_buffer[-50:])
    output_buffer = []
    running = process is not None and process.poll() is None
    return jsonify({'output': output, 'running': running})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
