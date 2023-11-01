import bcrypt
from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)
app.secret_key = "secret_key"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, username):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # decoded the hashed password

    def checkpass(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


with app.app_context():
    db.create_all()

@app.route("/")
def main():
    return render_template("index.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("logoinemail", False)  # use request.form.get with a default value
        password = request.form['logoinpassword']

        if email:
            user = User.query.filter_by(email=email).first()

            if user and user.checkpass(password):
                session['name'] = user.username
                session['email'] = user.email
                return redirect("/dashboard")
        
        return render_template('login.html', error="Invalid Data or Email Not Found")

    return render_template("login.html")



@app.route("/register",methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(username=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    
    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    if 'name' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template("dashboard.html", user=user)
    
    return redirect("/login")

@app.route("/logout")
def logout():
    session.pop("logoinemail", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, port=8000)