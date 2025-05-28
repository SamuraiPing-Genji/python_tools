import requests
from tqdm import tqdm

BASE_RAW = "https://raw.githubusercontent.com/google/oss-fuzz/master/projects"
BASE_API = "https://api.github.com/repos/google/oss-fuzz/contents/projects"

TARGET_KEYWORDS = [
    "iot", "embedded", "automation", "electric", "power", "energy",
    "ev", "grid", "modbus", "can", "mqtt", "zephyr", "nuttx", "opc", "sensor", "serial"
]

EXCLUDE_KEYWORDS = [
    "qemu", "emulate", "device", "usb", "bluetooth", "socket"
]


def get_project_links_from_github_api():
    print("Fetching project list via GitHub API...")
    headers = {"Accept": "application/vnd.github.v3+json"}
    response = requests.get(BASE_API, headers=headers)
    response.raise_for_status()
    items = response.json()
    print(items)
    return [(item["name"], item["html_url"]) for item in items if item["type"] == "dir"]


def keyword_filter(text):
    text_lower = text.lower()
    if not any(k in text_lower for k in TARGET_KEYWORDS):
        return False
    if any(k in text_lower for k in EXCLUDE_KEYWORDS):
        return False
    return True


def scan_project(name, url):
    readme_url = f"{BASE_RAW}/{name}/README.md"
    build_url = f"{BASE_RAW}/{name}/build.sh"

    readme_resp = requests.get(readme_url)
    build_resp = requests.get(build_url)

    text = (readme_resp.text if readme_resp.status_code == 200 else "") + \
           (build_resp.text if build_resp.status_code == 200 else "")
    
    if keyword_filter(text):
        return {
            "name": name,
            "url": url
        }
    return None


def main():
    candidates = []
    projects = get_project_links_from_github_api()
    for name, url in tqdm(projects, desc="Scanning", ncols=100):
        # print(f"Scanning {name}...")
        result = scan_project(name, url)
        if result:
            candidates.append(result)

    print("\n✅ Matched Projects:")
    for p in candidates:
        print(f"- {p['name']}: {p['url']}")


if __name__ == "__main__":
    main()
