from flask import Flask, render_template_string, request, jsonify
import subprocess
import threading
import queue

app = Flask(__name__)
output_queue = queue.Queue()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>JC Destroyer Panel</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #00ff00; padding: 20px; }
        #output { background: #000; padding: 20px; border-radius: 5px; height: 500px; overflow-y: auto; }
        input, button { padding: 10px; margin: 10px 0; font-size: 16px; }
        button { background: #00ff00; color: #000; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🚀 JC Destroyer Panel</h1>
    <div id="output"></div>
    <input type="text" id="command" placeholder="Enter command..." style="width: 80%">
    <button onclick="sendCommand()">Send</button>
    
    <script>
        function sendCommand() {
            const cmd = document.getElementById('command').value;
            fetch('/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            }).then(r => r.json()).then(data => {
                document.getElementById('output').innerHTML += data.output + '<br>';
                document.getElementById('command').value = '';
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/execute', methods=['POST'])
def execute():
    command = request.json.get('command', '')
    # Here you'd integrate with your destroyerjc.py script
    # For now, just echo the command
    return jsonify({'output': f'Received: {command}'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
