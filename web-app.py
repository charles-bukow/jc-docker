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
    <title>JC Destroyer - Remote Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0a0a0a; 
            color: #00ff00; 
            padding: 20px;
            height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00ff00; margin-bottom: 20px; text-shadow: 0 0 10px #00ff00; }
        #terminal { 
            background: #000; 
            padding: 20px; 
            border: 2px solid #00ff00;
            border-radius: 5px; 
            height: 60vh; 
            overflow-y: auto; 
            margin-bottom: 20px;
            font-size: 14px;
            line-height: 1.5;
        }
        .input-group {
            display: flex;
            gap: 10px;
        }
        input { 
            flex: 1;
            padding: 15px; 
            font-family: 'Courier New', monospace;
            font-size: 16px; 
            background: #1a1a1a;
            border: 2px solid #00ff00;
            color: #00ff00;
            border-radius: 5px;
        }
        button { 
            padding: 15px 30px; 
            background: #00ff00; 
            color: #000; 
            border: none; 
            cursor: pointer;
            font-weight: bold;
            font-size: 16px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        button:hover { background: #00cc00; transform: scale(1.05); }
        .output-line { margin: 2px 0; }
        .error { color: #ff0000; }
        .success { color: #00ff00; }
        .warning { color: #ffff00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 JC Destroyer - Remote Control Panel</h1>
        <div id="terminal">
            <div class="success">System ready. Waiting for commands...</div>
        </div>
        <div class="input-group">
            <input type="text" id="command" placeholder="Enter command or press Start to run scanner..." autofocus>
            <button onclick="sendCommand()">Send</button>
            <button onclick="startScanner()">Start Scanner</button>
        </div>
    </div>
    
    <script>
        const terminal = document.getElementById('terminal');
        const input = document.getElementById('command');
        
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
        
        function sendCommand() {
            const cmd = input.value.trim();
            if (!cmd) return;
            
            addOutput('> ' + cmd, 'warning');
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
                        if (line.trim()) addOutput(line);
                    });
                }
            })
            .catch(err => addOutput('Error: ' + err, 'error'));
        }
        
        function startScanner() {
            addOutput('Starting scanner...', 'success');
            fetch('/start', {method: 'POST'})
            .then(r => r.json())
            .then(data => addOutput(data.status, 'success'))
            .catch(err => addOutput('Error: ' + err, 'error'));
            
            // Poll for output
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
    output = '\\n'.join(output_buffer[-50:])  # Last 50 lines
    output_buffer = []
    running = process is not None and process.poll() is None
    return jsonify({'output': output, 'running': running})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
