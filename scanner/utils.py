# scanner/utils.py
import requests
from bs4 import BeautifulSoup

def scan_website(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Simulate discovery of usernames/passwords (educational purpose only)
            fake_credentials = [
                {"username": "admin", "role": "Administrator", "server": "Apache"},
                {"username": "user1", "role": "User", "server": "NGINX"}
            ]
            return {"status": "success", "data": fake_credentials}
        else:
            return {"status": "error", "message": f"Failed to access {url}."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
