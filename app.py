import data
from flask import Flask, render_template, url_for, redirect, request, session
import bcrypt


# put your code here
app = Flask(__name__)

# app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.secret_key = "super secret key"

if __name__ == "__main__":

    app.run()

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        if email in data.users and \
            verify_password(password, data.users[email]):

            session["email"] = email
            return redirect(url_for("index"))
        else:
            message = "wrong password"
            return render_template("login.html", message=message)

def verify_password(plain_text_password,hash_pass):
    hashed_bytes_password = hash_pass.encode("UTF-8")
    return bcrypt.checkpw(plain_text_password.encode("UTF-8"), \
                          hashed_bytes_password)

