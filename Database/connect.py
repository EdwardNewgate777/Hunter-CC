import sqlite3


class Connect_DB():
    def __init__(self):
        self.conn = sqlite3.connect('Database/Hunting.db')

    def add_hash(self, hash):
        cur = self.conn.cursor()

        req = "INSERT INTO C2(hash) VALUES(?)"
        cur.execute(req, (hash,))
        self.conn.commit()

    def check_hash(self, hash):
        cur = self.conn.cursor()
        req = "SELECT hash FROM C2 WHERE  hash=?"
        result = cur.execute(req, (hash,))

        if result.fetchone():
            return True
        else:
            return False

    def logout(self):
        self.conn.close()
