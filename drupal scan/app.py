from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import concurrent.futures

app = Flask(__name__)

# Helper to ensure URL format
def format_url(url):
    if not url.startswith('http'):
        url = 'http://' + url
    return url

def check_drupal_version(url):
    try:
        response = requests.get(f"{url}/CHANGELOG.txt")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for line in soup.text.splitlines():
                if "Drupal" in line:
                    return line.strip()
        return "Could not determine Drupal core version."
    except Exception as e:
        return f"Error: {str(e)}"

def check_theme_vulnerabilities(url):
    try:
        response = requests.get(f"{url}/sites/all/themes/")
        if response.status_code == 200:
            return "Themes folder is accessible, which could expose vulnerabilities."
        return "Themes folder is secured."
    except Exception as e:
        return f"Error: {str(e)}"

def check_module_vulnerabilities(url):
    try:
        response = requests.get(f"{url}/sites/all/modules/")
        if response.status_code == 200:
            return "Modules folder is accessible, which could expose vulnerabilities."
        return "Modules folder is secured."
    except Exception as e:
        return f"Error: {str(e)}"

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        required_headers = ["X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection", "Strict-Transport-Security"]
        missing_headers = [header for header in required_headers if header not in headers]
        if missing_headers:
            return f"Missing security headers: {', '.join(missing_headers)}"
        return "All necessary security headers are present."
    except Exception as e:
        return f"Error: {str(e)}"

def check_outdated_libraries(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = [script['src'] for script in soup.find_all('script') if 'src' in script.attrs]
        outdated = [script for script in scripts if 'jquery' in script or 'outdated' in script]
        if outdated:
            return f"Outdated libraries found: {', '.join(outdated)}"
        return "No outdated libraries found."
    except Exception as e:
        return f"Error: {str(e)}"

def check_user_enumeration(url):
    try:
        user_enum_url = f"{url}/?q=user"
        response = requests.get(user_enum_url)
        if "Access denied" not in response.text:
            return "User enumeration might be possible."
        return "User enumeration seems protected."
    except Exception as e:
        return f"Error: {str(e)}"

def check_config_issues(url):
    try:
        config_files = [f"{url}/sites/default/settings.php", f"{url}/sites/default/config.php"]
        for config_file in config_files:
            response = requests.get(config_file)
            if response.status_code == 200:
                return f"Configuration file exposed: {config_file}"
        return "No configuration issues found."
    except Exception as e:
        return f"Error: {str(e)}"

# Run vulnerability checks in parallel to speed up processing
def run_scans(url):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(check_drupal_version, url): 'core_version',
            executor.submit(check_theme_vulnerabilities, url): 'theme_vulns',
            executor.submit(check_module_vulnerabilities, url): 'module_vulns',
            executor.submit(check_security_headers, url): 'security_headers',
            executor.submit(check_outdated_libraries, url): 'outdated_libs',
            executor.submit(check_user_enumeration, url): 'user_enum',
            executor.submit(check_config_issues, url): 'config_issues'
        }
        results = {futures[future]: future.result() for future in concurrent.futures.as_completed(futures)}
    return results

@app.route('/', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form['url']
        url = format_url(url)

        # Run the scans concurrently
        results = run_scans(url)

        return render_template('index.html', url=url, results=results)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
