import requests
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retries = Retry(total=2, connect=False, read=False, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retries)
session.mount('http://', adapter)
session.mount('https://', adapter)

start = time.time()
try:
    session.get('http://192.0.2.1:80', timeout=2)
except Exception as e:
    pass
print(f"Elapsed: {time.time() - start:.2f}s")
