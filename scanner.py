import hashlib
from time import sleep

import requests
from Database.connect import Connect_DB

REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
API_KEY = 'df4b02e3a1e82e1fbf374c3eac99f106576af31ee12f0fd1e0666b79b40550e5'


class Scanner():

    def __init__(self, filename=''):
        self.filename = filename
        self.conn = Connect_DB()
        self.hash = ''

    def get_filename(self):
        return self.filename

    def get_hash(self):
        if not self.hash:
            calc_hash = hashlib.sha256()
            with open(self.filename, "rb") as f:
                for bytes_block in iter(lambda: f.read(4096), b""):
                    calc_hash.update(bytes_block)

            self.hash = calc_hash.hexdigest()
        return self.hash

    def upload_malware(self):
        params = {'apikey': API_KEY}
        files = {'file': ('myfile.exe', open(self.filename, 'rb'))}
        requests.post(SCAN_URL, files=files, params=params)

    def isMalware(self):
        hash = self.get_hash()

        if self.conn.check_hash(hash):
            print("Virus connu")
            return True
        else:
            params = {'apikey': API_KEY, 'resource': hash}
            response = requests.get(REPORT_URL, params=params)
            response_code = response.json()['response_code']

            if response_code == 0:
                self.upload_malware()
                while(True):
                    sleep(20)
                    response = requests.get(REPORT_URL, params=params)
                    if response.json()['response_code'] == -2:
                        continue
                    else:
                        break

            result = response.json()['positives']
            if result >= 10:
                self.conn.add_hash(self.hash)
                return True

            else:
                return False
