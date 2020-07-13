import sqlite3


class Connect_DB():
    def __init__(self):
        self.conn = sqlite3.connect('Database/Hunting.db')

    def add_hash(self, hash, isMalware="True"):
        cur = self.conn.cursor()

        req = "INSERT INTO C2(hash, IsMalware) VALUES(?, ?)"
        if isMalware:
            cur.execute(req, (hash, 1))
        else:
            cur.execute(req, (hash, 0))

        self.conn.commit()

    def check_hash(self, hash, isMalware="True"):
        cur = self.conn.cursor()

        if isMalware:
            req = "SELECT hash FROM C2 WHERE  hash=? AND IsMalware=1"
        else:
            req = "SELECT hash FROM C2 WHERE  hash=?"

        result = cur.execute(req, (hash,))

        if result.fetchone():
            return True
        else:
            return False

    def logout(self):
        self.conn.close()
