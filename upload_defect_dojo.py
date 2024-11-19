import os
import re
import requests
import tomli
import argparse
from pathlib import Path
from datetime import datetime

def load_dojo_config(config_path):
    with open(config_path, 'rb') as f:
        return tomli.load(f)

def get_or_create_product(host, token, product_data):
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(
        f'{host}/api/v2/products/?name={product_data["name"]}',
        headers=headers
    )
    if response.status_code == 200:
        data = response.json()
        if data.get('results') and len(data['results']) > 0:
            return data['results'][0]['id']
    
    prod_type_response = requests.get(
        f'{host}/api/v2/product_types/',
        headers=headers
    )
    if prod_type_response.status_code != 200:
        raise ValueError(f"Failed to get product types: {prod_type_response.text}")
    
    prod_types = prod_type_response.json().get('results', [])
    prod_type_id = next((pt['id'] for pt in prod_types if pt.get('name') == product_data['type']), None)
    
    if prod_type_id is None:
        raise ValueError(f"Product type '{product_data['type']}' not found")
    
    create_data = {
        'name': product_data['name'],
        'prod_type': prod_type_id,
        'description': 'Automated fuzzing results'
    }
    
    response = requests.post(
        f'{host}/api/v2/products/',
        headers=headers,
        json=create_data
    )
    
    if response.status_code != 201:
        raise ValueError(f"Failed to create product: {response.text}")
    
    return response.json()['id']

def get_or_create_engagement(host, token, product_id, engagement_data):
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(
        f'{host}/api/v2/engagements/?product={product_id}&name={engagement_data["name"]}',
        headers=headers
    )
    
    if response.status_code == 200:
        data = response.json()
        if data.get('results') and len(data['results']) > 0:
            return data['results'][0]['id']
    
    create_data = {
        'name': engagement_data['name'],
        'product': product_id,
        'target_start': '2024-01-01',
        'target_end': '2030-12-31',
        'status': 'In Progress',
        'engagement_type': 'CI/CD',
        'deduplication_on_engagement': False
    }
    
    response = requests.post(
        f'{host}/api/v2/engagements/',
        headers=headers,
        json=create_data
    )
    
    if response.status_code != 201:
        raise ValueError(f"Failed to create engagement: {response.text}")
    
    return response.json()['id']

def get_or_create_test(host, token, engagement_id, test_data):
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(f'{host}/api/v2/test_types/', headers=headers)
    test_type_id = next((tt['id'] for tt in response.json().get('results', [])
                        if tt.get('name') == 'Security Research'), None)
    
    if test_type_id is None:
        raise ValueError("Could not find Security Research test type")
    
    response = requests.get(
        f'{host}/api/v2/tests/?engagement={engagement_id}&test_type={test_type_id}',
        headers=headers
    )
    
    if response.status_code == 200:
        tests = response.json()
        if tests.get('results') and len(tests['results']) > 0:
            return tests['results'][0]['id']
    
    create_data = {
        'engagement': engagement_id,
        'test_type': test_type_id,
        'target_start': '2024-01-01',
        'target_end': '2024-12-31',
        'title': f"Fuzzing Test - {test_data['test_type']}"
    }
    
    response = requests.post(
        f'{host}/api/v2/tests/',
        headers=headers,
        json=create_data
    )
    
    if response.status_code != 201:
        raise ValueError(f"Failed to create test: {response.text}")
    
    return response.json()['id']

def get_shortened_filename(original_filename):
    hash_match = re.search(r'[a-f0-9]{32}', original_filename)
    if hash_match:
        return f"details_{hash_match.group(0)}"
        
    crash_hash_match = re.search(r'crash-([a-f0-9]+)', original_filename)
    if crash_hash_match:
        return f"crash-{crash_hash_match.group(1)}"
        
    return original_filename[:100]

def get_unique_filename(base_title):
    """Add timestamp to filename"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name, ext = os.path.splitext(base_title)
    return f"{name}_{timestamp}{ext}"

def upload_file(host, token, finding_id, file_path, title):
    headers = {'Authorization': f'Token {token}'}
    unique_title = get_unique_filename(title)
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {'title': unique_title}
        response = requests.post(
            f'{host}/api/v2/findings/{finding_id}/files/',
            headers=headers,
            files=files,
            data=data
        )
        if response.status_code != 201:
            print(f"Error uploading file: {response.text}")
            return False
    return True

def parse_triage_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    patterns = {
        'summary': r'Summary:\s*(.*?)(?:\n|$)',
        'crash_id': r'Testcase:\s*(.*?)(?:\n|$)',
        'crash_bucket': r'Crash bucket:\s*(.*?)(?:\n|$)',
        'command_line': r'Command line:\s*(.*?)(?:\n|$)',
        'asan_report': r'ASAN Report:\n(.*?)(?:\n\nCrash context:|$)'
    }
    
    results = {
        key: (re.search(pattern, content, re.MULTILINE | re.DOTALL).group(1).strip() 
              if re.search(pattern, content, re.MULTILINE | re.DOTALL) 
              else f'No {key} available')
        for key, pattern in patterns.items()
    }
    
    results.update({
        'full_content': content,
        'triage_file': file_path
    })
    
    return results
import os
import re
import requests
import tomli
import argparse
from pathlib import Path
from datetime import datetime

# [Previous functions remain unchanged]

def get_unique_filename(base_title):
    """Add timestamp to filename and ensure .txt extension"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = os.path.splitext(base_title)[0]  # Get name without extension
    return f"{name}_{timestamp}.txt"  # Always add .txt extension

def upload_file(host, token, finding_id, file_path, title):
    headers = {'Authorization': f'Token {token}'}
    # Ensure title ends with .txt
    if not title.endswith('.txt'):
        title += '.txt'
    unique_title = get_unique_filename(title)
    
    with open(file_path, 'rb') as f:
        files = {'file': (unique_title, f)}  # Explicitly set filename in files
        data = {'title': unique_title}
        response = requests.post(
            f'{host}/api/v2/findings/{finding_id}/files/',
            headers=headers,
            files=files,
            data=data
        )
        if response.status_code != 201:
            print(f"Error uploading file: {response.text}")
            return False
    return True

def determine_severity(asan_report):
    if any(x in asan_report.lower() for x in ['write', '-write-', 'store', 'heap-buffer-overflow']):
        return "Critical", "S0"
    elif 'segv' in asan_report.lower() or 'sigsegv' in asan_report.lower():
        return "High", "S1"
    elif any(x in asan_report.lower() for x in ['read', '-read-', 'load', 'exception']):
        return "Medium", "S2"
    return "High", "S1"  # Default to High if uncertain

def clean_asan_report(asan_report):
    """Clean ASAN report by removing or replacing problematic markdown characters"""
    cleaned_lines = []
    for line in asan_report.split('\n'):
        # Replace '#' at the start of lines with a frame number indicator
        if line.strip().startswith('#'):
            line = 'Frame' + line[1:]
        cleaned_lines.append(line)
    return '\n'.join(cleaned_lines)

def determine_severity(asan_report):
    if any(x in asan_report.lower() for x in ['write', '-write-', 'store', 'heap-buffer-overflow']):
        return "Critical", "S0"
    elif 'segv' in asan_report.lower() or 'sigsegv' in asan_report.lower():
        return "High", "S1"
    elif any(x in asan_report.lower() for x in ['read', '-read-', 'load', 'exception']):
        return "Medium", "S2"
    return "High", "S1"  # Default to High if uncertain

def upload_finding(host, token, test_id, finding_data):
    headers = {
        'Authorization': f'Token {token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(f'{host}/api/v2/test_types/', headers=headers)
    found_by_id = next((t['id'] for t in response.json().get('results', [])
                       if t.get('name') == 'Security Research'), None)
    
    if found_by_id is None:
        raise ValueError("Could not find Security Research test type")
    
    severity, numerical_severity = determine_severity(finding_data['asan_report'])
    
    # Clean the ASAN report
    cleaned_asan_report = clean_asan_report(finding_data['asan_report'])
    
    finding = {
        "title": finding_data['summary'].split(' in ', 1)[-1],
        "test": test_id,
        "description": f"""**Crash Details:**
- Crash ID: {finding_data['crash_id']}
- Crash Bucket: {finding_data['crash_bucket']}
- Summary: {finding_data['summary']}

**Steps to Reproduce:**
1. Execute command: `{finding_data['command_line']}`
2. Use input file: `{finding_data['crash_id']}`

**ASAN Report:**
```
{cleaned_asan_report.strip()}
```

**Full Triage Output:**
```
{finding_data['full_content'].strip()}
```""",
        "severity": severity,
        "numerical_severity": numerical_severity,
        "found_by": [found_by_id],
        "verified": False,
        "active": True
    }

    find_response = requests.post(
        f'{host}/api/v2/findings/',
        headers=headers,
        json=finding
    )
    
    if find_response.status_code != 201:
        print(f"Error uploading finding {finding_data['crash_id']}: {find_response.text}")
        return None
    
    finding_id = find_response.json()['id']
    
    # Upload triage file with .txt extension
    shortened_name = get_shortened_filename(os.path.basename(finding_data['triage_file']))
    if not shortened_name.endswith('.txt'):
        shortened_name += '.txt'
    upload_file(host, token, finding_id, finding_data['triage_file'], shortened_name)
    
    # Extract and upload crash file
    if finding_data['crash_id'].startswith('named_crashes/'):
        crash_filename = os.path.basename(finding_data['crash_id'])
        crash_dir = os.path.dirname(finding_data['triage_file'])
        named_crashes_dir = os.path.join(os.path.dirname(crash_dir), 'named_crashes')
        crash_input_path = os.path.join(named_crashes_dir, crash_filename)
        
        if os.path.exists(crash_input_path):
            crash_name = crash_filename
            shortened_name = get_shortened_filename(crash_name)
            if not shortened_name.endswith('.txt'):
                shortened_name += '.txt'
            upload_file(host, token, finding_id, crash_input_path, shortened_name)
    
    return finding

def main():
    parser = argparse.ArgumentParser(description='Upload AFL triage results to DefectDojo')
    parser.add_argument('--token', required=True, help='DefectDojo API token')
    parser.add_argument('--host', required=True, help='DefectDojo host URL')
    parser.add_argument('--config', default='dojo.toml', help='Path to dojo.toml config file')
    parser.add_argument('--triage-dir', default='.', help='Directory containing triage files')
    
    args = parser.parse_args()
    config = load_dojo_config(args.config)
    
    product_id = get_or_create_product(args.host, args.token, config['product'])
    engagement_id = get_or_create_engagement(args.host, args.token, product_id, config['engagement'])
    test_id = get_or_create_test(args.host, args.token, engagement_id, config['test'])
    
    triage_dir = Path(args.triage_dir)
    for file_path in triage_dir.glob('afltriage_*.txt'):
        print(f"Processing {file_path}")
        finding_data = parse_triage_file(file_path)
        result = upload_finding(args.host, args.token, test_id, finding_data)
        if result:
            print(f"Successfully uploaded {finding_data['crash_id']}")

if __name__ == '__main__':
    main()
