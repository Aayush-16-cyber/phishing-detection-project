from flask import Flask, render_template, request, redirect, url_for, session
import joblib
import re
import tldextract
import pandas as pd
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "supersecretkey123"

model = joblib.load("model/phishing_model.pkl")

DATABASE = "database.db"


# ----------------------------
# DATABASE INIT
# ----------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT,
            result TEXT,
            confidence REAL,
            risk TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("SELECT * FROM users WHERE username='admin'")

    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username,password,role) VALUES (?,?,?)",
            ("admin", generate_password_hash("admin123"), "admin")
        )

    conn.commit()
    conn.close()


# ----------------------------
# RISK CLASSIFICATION
# ----------------------------
def get_risk_level(result, confidence):

    if result == "SAFE":
        return "LOW"

    if confidence >= 80:
        return "HIGH"

    elif confidence >= 50:
        return "MEDIUM"

    else:
        return "LOW"


# ----------------------------
# FEATURE EXTRACTION
# ----------------------------
def extract_features(url):

    features = {}

    features['url_length'] = len(url)
    features['dots'] = url.count('.')
    features['slashes'] = url.count('/')
    features['special_chars'] = len(re.findall(r'[@?&=%-]', url))
    features['https'] = 1 if url.startswith("https") else 0

    keywords = ['login','verify','secure','account','bank','update']

    features['suspicious_words'] = sum(
        1 for word in keywords if word in url.lower()
    )

    ext = tldextract.extract(url)

    features['domain_length'] = len(ext.domain)

    return pd.DataFrame([features])


# ----------------------------
# PUBLIC HOME
# ----------------------------
@app.route("/", methods=["GET", "POST"])
def home():

    result_display = None

    if request.method == "POST":

        url = request.form["url"]

        features = extract_features(url)

        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1]

        confidence = round(probability * 100, 2)

        if prediction == 1:
            result = "PHISHING"
        else:
            result = "SAFE"
            confidence = round((1 - probability) * 100, 2)

        risk = get_risk_level(result, confidence)

        result_display = f"{result} - {confidence}% (Risk: {risk})"

        if "user_id" in session:

            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO detections (user_id,url,result,confidence,risk,timestamp)
                VALUES (?,?,?,?,?,?)
            """,(session["user_id"],url,result,confidence,risk,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            conn.commit()
            conn.close()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM detections")
    total_searches = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE result='SAFE'")
    total_safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE result='PHISHING'")
    total_phishing = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "index.html",
        result=result_display,
        total_searches=total_searches,
        total_safe=total_safe,
        total_phishing=total_phishing
    )


# ----------------------------
# REGISTER
# ----------------------------
@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:

            cursor.execute(
                "INSERT INTO users (username,password,role) VALUES (?,?,?)",
                (username,password,"user")
            )

            conn.commit()

            user_id = cursor.lastrowid

            session["user_id"] = user_id
            session["username"] = username
            session["role"] = "user"

        except:

            conn.close()

            return render_template("register.html", error="Username already exists")

        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("register.html")


# ----------------------------
# LOGIN
# ----------------------------
@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]

            if user[3] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")


# ----------------------------
# USER DASHBOARD
# ----------------------------
@app.route("/dashboard", methods=["GET","POST"])
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    result_display = None

    if request.method == "POST":

        url = request.form["url"]

        features = extract_features(url)

        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1]

        confidence = round(probability * 100, 2)

        if prediction == 1:
            result = "PHISHING"
        else:
            result = "SAFE"
            confidence = round((1 - probability) * 100, 2)

        risk = get_risk_level(result, confidence)

        result_display = f"{result} - {confidence}% (Risk: {risk})"

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO detections (user_id,url,result,confidence,risk,timestamp)
            VALUES (?,?,?,?,?,?)
        """,(session["user_id"],url,result,confidence,risk,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        conn.close()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp,url,result,confidence,risk
        FROM detections
        WHERE user_id=?
        ORDER BY id DESC
    """,(session["user_id"],))

    history = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM detections WHERE user_id=? AND result='SAFE'",(session["user_id"],))
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE user_id=? AND result='PHISHING'",(session["user_id"],))
    phishing = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "user_dashboard.html",
        username=session["username"],
        result=result_display,
        search_history=history,
        safe=safe,
        phishing=phishing
    )


# ----------------------------
# ADMIN DASHBOARD
# ----------------------------
@app.route("/admin", methods=["GET"])
def admin_dashboard():

    if "role" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT users.username, detections.url,
               detections.result, detections.confidence,
               detections.risk,
               detections.timestamp,
               detections.id
        FROM detections
        JOIN users ON detections.user_id = users.id
        ORDER BY detections.id DESC
    """)

    data = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM detections")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE result='SAFE'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE result='PHISHING'")
    phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM detections WHERE risk='HIGH'")
    high_risk = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "admin.html",
        data=data,
        total=total,
        safe=safe,
        phishing=phishing,
        high_risk=high_risk
    )


# ----------------------------
# DELETE RECORD
# ----------------------------
@app.route("/delete/<int:record_id>")
def delete_record(record_id):

    if "role" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM detections WHERE id=?", (record_id,))

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


# ----------------------------
# LOGOUT
# ----------------------------
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":

    init_db()

    app.run(debug=True)