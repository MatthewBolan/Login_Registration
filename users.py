from mysqlconnection import connectToMySQL

import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

from flask import flash

class User:


    def __init__(self, data):

        self.id = data['id']

        self.first_name = data['first_name']

        self.last_name = data['last_name']

        self.email = data['email']

        self.password = data['password']

        self.created_at = data['created_at']

        self.updated_at = data['updated_at']






    @classmethod

    def save_user(cls, data):

        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s)"

        result = connectToMySQL('lr_users_schema').query_db(query, data)

        return result


    

    @classmethod

    def user_by_id(cls,data):

        query = "SELECT * FROM users WHERE id = %(id)s"

        result = connectToMySQL ('lr_users_schema').query_db(query,data)

        return  cls (result[0])



    @classmethod

    def user_by_email(cls,data):

        query = "SELECT * FROM users WHERE email = %(email)s"

        result = connectToMySQL ('lr_users_schema').query_db(query,data)

        if len (result) < 1:

            return False

        return cls (result[0])



    @staticmethod

    def validate(user):
        
        valid = True

        query = "SELECT * FROM users WHERE email = %(email)s"

        results = connectToMySQL('lr_users_schema').query_db(query,user)

        if len (results) >= 1:

            flash ("Email Has Been Used. Please Try Again!", "register" )

            valid = False
        
        if not EMAIL_REGEX.match (user['email']):

            flash ("Email Not Valid. Please Make Sure Your Email Is Spelled Accordingly!", "register")

            valid = False

        if len (user['first_name']) < 3:

            flash ("First Name Too Short!", "register")

            valid = False

        if len (user['last_name']) < 3:

            flash ("Last Name Too Short!", "register")

            valid = False

        if len (user['password']) < 8:

            flash ("Eight Characters Max!", "register")

            valid = False
        
        if user ['password'] != user ['confirm']:

            flash ("Invalid! Please Check Passwords.")

            valid = False

        else:

            return valid
