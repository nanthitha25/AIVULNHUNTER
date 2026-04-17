import time
import bcrypt

start = time.time()
ok = bcrypt.checkpw(b"admin123", b"$2b$12$Dg63mGQ6kvQB8JvIcSUA.O8Q0cjwePVYk8luacKLV5jD3Nf3JfA1e")
print("OK?", ok)
print("Time taken:", time.time() - start)
