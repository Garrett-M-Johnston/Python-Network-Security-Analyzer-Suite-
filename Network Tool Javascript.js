// JavaScript file

document.addEventListener('DOMContentLoaded', function() {
    const startScanButton = document.getElementById('startScan');
    const stopScanButton = document.getElementById('stopScan');
    const analyzeUrlsButton = document.getElementById('analyzeUrls');
    const analyzeEmailButton = document.getElementById('analyzeEmail');
    const analyzePasswordButton = document.getElementById('analyzePassword');
    const generatePasswordButton = document.getElementById('generatePassword');

    startScanButton.addEventListener('click', function() {
        const targetIp = document.getElementById('targetIp').value;
        const startPort = document.getElementById('startPort').value;
        const endPort = document.getElementById('endPort').value;
        fetch('/start_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: targetIp, start_port: startPort, end_port: endPort })
        }).then(response => response.json()).then(data => {
            console.log(data);
        });
    });

    stopScanButton.addEventListener('click', function() {
        fetch('/stop_scan', {
            method: 'POST'
        }).then(response => response.json()).then(data => {
            console.log(data);
        });
    });

    analyzeUrlsButton.addEventListener('click', function() {
        const urls = document.getElementById('urls').value.split('\n');
        fetch('/analyze_urls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: urls })
        }).then(response => response.json()).then(data => {
            console.log(data);
        });
    });

    analyzeEmailButton.addEventListener('click', function() {
        const emailContent = document.getElementById('emailContent').value;
        fetch('/analyze_email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_content: emailContent })
        }).then(response => response.json()).then(data => {
            console.log(data);
        });
    });

    analyzePasswordButton.addEventListener('click', function() {
        const password = document.getElementById('password').value;
        fetch('/analyze_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password })
        }).then(response => response.json()).then(data => {
            console.log(data);
        });
    });

    generatePasswordButton.addEventListener('click', function() {
        fetch('/generate_password', {
            method: 'POST'
        }).then(response => response.json()).then(data => {
            document.getElementById('password').value = data.password;
        });
    });
});

console.log("Hello, World!");