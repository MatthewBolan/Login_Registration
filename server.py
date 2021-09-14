import re

from users import User

from flask import Flask, render_template, request, redirect, session, flash

app = Flask(__name__)

app.secret_key = 'ServerKey'

from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)



@app.route('/')
def index():

    return redirect("/register/login")




@app.route('/register/login')
def register_login_page():

    return render_template("register_login.html")


    
@app.route('/user/register', methods=['POST'])
def registered_user():

    if not User.validate(request.form):

        return redirect('/')

    data = {

        "first_name": request.form ['first_name'],

        "last_name": request.form ['last_name'],

        "email": request.form ['email'],

        "password": bcrypt.generate_password_hash(request.form['password']) 

    }

    id = User.save_user(data)

    session['user_id'] = id

    return redirect ('/welcome')





@app.route('/welcome')
def welcome():

    if 'user_id' not in session:

        return redirect ('/logout')

    data = {

        'id': session ['user_id']

    }

    return render_template("welcome.html", user = User.user_by_id(data))



@app.route('/user/login', methods=['POST'])
def login_user():

    user = User.user_by_email(request.form)


    if not user:

        flash ("Email Not Valid. Please Try Again!" , "login")

        return redirect ('/')


    if not bcrypt.check_password_hash (user.password, request.form ['password']):

        flash ("Password Not Valid. Please Try Again!", "login")

        return redirect ('/')


    session ['user_id'] = user.id

    return redirect('/welcome')





@app.route('/logout')
def logout():

    session.clear()

    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)