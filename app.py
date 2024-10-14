from flask import Flask, request, jsonify, render_template
import requests
import re
from bs4 import BeautifulSoup
from sqltags import sqltags 
from tags import xsstags
from phptags import phppayload
from ostags import ospayloads
from rubytags import rubycodes
from pearltag import pearlcode
from javapayload import javascriptpayloads
import threading
from logcodes import logtags
from sspayloads import sstags
from ccpayloads import ccptags
from exposeloads import backuptags
from vwspayloads import vwtags
from urlpayloads import urltags
from cstipayloads import cstitags
from httppayloads import  taght
from jpayloads import jtags
import time

app = Flask(__name__)

# Function to find REST, SOAP, WebSocket, and other APIs
def detect_apis(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to http if no protocol is provided
    

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        api_results = {
            "REST APIs": [],
            "SOAP APIs": [],
            "WebSocket APIs": [],
            "Browser APIs": [],
            "iOS/Android APIs": [],
            "Partner APIs": [],
            "Public APIs": [],
            "Private APIs": []
        }

        # Detect REST APIs
        rest_api_patterns = re.findall(r'/api/.*', response.text)
        if rest_api_patterns:
            api_results["REST APIs"] = rest_api_patterns

        # Detect SOAP APIs
        if 'soapaction' in response.headers.get('Content-Type', '').lower() or '.wsdl' in response.text:
            api_results["SOAP APIs"].append(url)

        # Detect WebSocket APIs
        ws_match = re.search(r'(ws://|wss://)', response.text)
        if ws_match:
            api_results["WebSocket APIs"].append(ws_match.group())

        # Detect Browser APIs
        browser_api_patterns = ['fetch', 'XMLHttpRequest', 'navigator', 'window.location']
        for pattern in browser_api_patterns:
            if pattern in response.text:
                api_results["Browser APIs"].append(f"Found {pattern} API usage")

        # Detect iOS/Android APIs
        if re.search(r'android|ios|apk|ipa', response.text, re.IGNORECASE):
            api_results["iOS/Android APIs"].append("Mobile-specific API detected")

        # Detect Partner APIs
        partner_api_patterns = ['partner', 'affiliate', 'integration']
        for pattern in partner_api_patterns:
            if pattern in response.text:
                api_results["Partner APIs"].append(f"Found {pattern} API usage")

        # Detect Public/Private APIs
        if re.search(r'public', response.text, re.IGNORECASE):
            api_results["Public APIs"].append("Public API detected")
        if re.search(r'private', response.text, re.IGNORECASE):
            api_results["Private APIs"].append("Private API detected")

        return api_results

    except Exception as e:
        return {"error": str(e)}

def check_xss(api_url, param, result ):
    xss_payloads = xsstags  # define the list of XSS payloads
    for payload in xss_payloads:
        data = {param: payload}
        response = requests.get(api_url, params=data)
        if payload in response.text:
            result["XSS"] = f"Potential XSS vulnerability detected with payload: {payload}"
            return
    result["XSS"] = "No XSS vulnerability detected."

def check_sql_injection(api_url, param, result ):
    sql_payloads = sqltags
    for payload in sql_payloads:
        data = {param: payload}
        response = requests.post(api_url, params=data)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            result["SQL Injection"] = f"Potential SQL Injection vulnerability with payload: {payload}"
            return
    result["SQL Injection"] = "No SQL Injection vulnerability detected."

def check_os_command_injection(api_url, param, result ):
    os_command_payloads = ospayloads
    for payload in os_command_payloads:
        data = {param: payload}
        response = requests.get(api_url, params=data)
        if "root" in response.text or "bin" in response.text or "daemon" in response.text:
            result["OS Command Injection"] = f"Potential OS Command Injection vulnerability with payload: {payload}"
            return
    result["OS Command Injection"] = "No OS Command Injection vulnerability detected."

def check_php_code_injection(api_url, param, result  ):
    php_payloads = phppayload
    for payload in php_payloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "phpinfo" in response.text:
                result["PHP Code Injection"] = f"Potential PHP Code Injection vulnerability detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["PHP Code Injection"] = "No PHP Code Injection vulnerability detected."
    
def check_CSTI(api_url, param, result ):
    # Extract tags from the csti_tags dictionary
    cstipayloads = cstitags
    
    for payload in cstipayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.headers or "AngularJS, VueJS, Mavo, React, Ember" in response.text:
                result["client side template injection"] = f"Client-side template injection vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["client side template injection"] = "No client-side template injection vulnerability detected."

def check_Log4jremotecode_injection(api_url, param, result,):
    logcodes = logtags
    for payload in logcodes:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "log4" in response.text:
                result["log4 Code Injection"] = f"Log 4 remote code injection vulnerability detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["Log4 Code Injection"] = "No Log 4 injection Code Injection vulnerability detected."

def check_serversideTemplateinjection(api_url, param, result):
    sspayloads = sstags
    for payload in sspayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "phpinfo" in response.text:
                result["server side Template injection"] = f"server side Template injection detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["server side Template injection"] = "NO server side Template injection   vulnerability detected."

def check_outdated_javascript(api_url, param, result):
    jpayloads = jtags
    for payload in jpayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "phpinfo" in response.text:
                result["java outdated libraries"] = f"outdated java libraries detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["server side Template injection"] = "NO outdated javalobraries detected."

def check_client_side_prototype_pollution(api_url, param, result):
    ccpayloads = ccptags
    for payload in ccpayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "client side pollution" in response.text:
                result["server side Template injection"] = f"server side Template injection detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["server side Template injection"] = "NO server side Template injection   vulnerability detected."

def check_exposed_backup_files(api_url, param, result, ):
    exposeloads =backuptags
    for payload in exposeloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "backupfiles" in response.text:
                result["Exposed Backup files "] = f"BACkup file detected with payload: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["Exposed Backup files"] = "No Exposed backup filed detected."

def check_ViewState_remote_code_execution(api_url, param, result):
    vwspayloads = vwtags
    for payload in vwspayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "APS.NET" in response.text:
                result["view state remote code "] = f" ViewState remote code execution vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["view state remote code"] = "NO ViewState remote code execution vulnerability detected"        

def check_rubycode_inejection(api_url, param, result):
    rubytags = rubycodes
    for payload in rubytags:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "Rubycode" in response.text:
                result["Ruby code "] = f" ruby code injection Injection vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["Ruby code injection"] = "NO Ruby  injection  vulnerability detected"    

def check_javascript_injection(api_url, param, result):
    javapayloads = javascriptpayloads
    for payload in javapayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.text or "javacode, .js" in response.text:
                result["Java code injection"] = f" JAVA code injection Injection vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["Java code injection"] = "java  injection  vulnerability detected"    

def check_Request_URL_Override(api_url, param, result):
    urlpayloads = urltags
    for payload in urlpayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.headers or "url" in response.text:
                result["Request URL Override "] = f" Request URL Override vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result["Request URL Override"] = "Request URL Override execution vulnerability detected."

def check_HTTP_Request_Smuggling(api_url, param, result):
    httppayloads = taght
    for payload in httppayloads:
        data = {param: payload}
        try:
            response = requests.get(api_url, params=data)
            if "root" in response.headers or "url" in response.text:
                result[" HTTP/1.1 Request Smuggling "] = f"  HTTP/1.1 Request Smuggling vulnerability detected: {payload}"
                return
        except requests.exceptions.RequestException:
            continue
    result[" HTTP/1.1 Request Smuggling"] = "No  HTTP/1.1 Request Smuggling vulnerability detected."

def check_http_methods(api_url):
    try:
        response = requests.options(api_url)
        if 'Allow' in response.headers:
            allowed_methods = response.headers['Allow']
            return f"Supported HTTP Methods: {allowed_methods}"
        else:
            return "No HTTP methods detected via OPTIONS."
    except Exception as e:
        return f"Error checking HTTP methods: {str(e)}"

def check_security_headers(api_url):
    security_headers = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]
    
    try:
        response = requests.get(api_url)
        missing_headers = []
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
                
        if missing_headers:
            return f"Missing security headers: {', '.join(missing_headers)}"
        else:
            return "All important security headers are present."
        
    except requests.exceptions.RequestException as e:
        return f"Error fetching the URL: {str(e)}"

def check_authentication(api_url):
    try:
        response = requests.get(f"{api_url}/auth")
        return response.status_code == 200  # or any other logic for checking auth
    except Exception as e:
        return f"Error during authentication check: {e}"

def check_sensitive_data(api_url):
    try:
        response = requests.get(f"{api_url}/sensitive-data")
        return response.status_code == 200 and response.json().get('sensitive') is not None
    except Exception as e:
        return f"Error during sensitive data check: {e}"

def scan_api_multithread(api_url):
    result = {}
    threads = []

    if not api_url.startswith(('http://', 'https://')):
        api_url = 'http://' + api_url


    result['Supported HTTP Methods'] = check_http_methods(api_url)
    result['Missing Security Headers'] = check_security_headers(api_url)
    result['Authentication Check'] = check_authentication(api_url)
    result['Sensitive Data Check'] = check_sensitive_data(api_url)

    threads.append(threading.Thread(target=check_sql_injection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_os_command_injection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_xss, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_php_code_injection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_Log4jremotecode_injection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_serversideTemplateinjection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_client_side_prototype_pollution, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_exposed_backup_files, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_ViewState_remote_code_execution, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_Request_URL_Override, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_CSTI, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_rubycode_inejection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_javascript_injection, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_HTTP_Request_Smuggling, args=(api_url, 'param', result)))
    threads.append(threading.Thread(target=check_outdated_javascript, args=(api_url, 'param', result)))


    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    return result

@app.route('/scan', methods=['POST'])
def api_scan():
    api_url = request.form['api_url']
    api_detection = detect_apis(api_url)
    detailed_scan = scan_api_multithread(api_url)
    result = {"API Detection": api_detection, "Detailed Scan": detailed_scan}
    return jsonify(result)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
