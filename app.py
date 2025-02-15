from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify,send_file,send_from_directory
import mysql.connector
from mysql.connector import Error
import plotly.io as pio
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from flask_session import Session
from flask_socketio import SocketIO, emit
import threading
import time  # Import time for the sleep function
from werkzeug.security import generate_password_hash, check_password_hash
import yaml
from collections import defaultdict
import plotly.express as px
import json
import os
import shutil
from PIL import Image, ImageDraw
import matplotlib.pyplot as plt
import random
import plotly
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import cv2
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

socketio = SocketIO(app)
comp_id = None
br_id = None



# Function to get connection to master_db from the YAML configuration file
def get_master_db_connection():
    try:
        with open('db_config.yaml', 'r') as yaml_file:
            db_config = yaml.safe_load(yaml_file)
        connection = mysql.connector.connect(**db_config)
        if connection:
            return connection
    except mysql.connector.Error as e:
        print(f"Error connecting to master_db: {e}")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
    return None

# Function to get user's database details from master_db
def get_user_db_details(email, password):
    try:
        connection = get_master_db_connection()
        if not connection:
            return None

        cursor = connection.cursor(dictionary=True)

        # Call the stored procedure to get user's DB details
        cursor.callproc('SP_fetch_user_db_details', [email, password])
        
        user_db_details = None
        for result in cursor.stored_results():
            user_db_details = result.fetchone()
            
        cursor.close()
        connection.close()

        return user_db_details
    except mysql.connector.Error as e:
        print(f"Error fetching user's DB details: {e}")
        return None

def get_dynamic_db_connection(db_details):
    try:
        connection = mysql.connector.connect(
            host=db_details['db_server_ip'],
            user=db_details['db_user_name'],
            password=db_details['db_pwd'],
            database=db_details['db_name']
        )
        return connection
    except mysql.connector.Error as e:
        print(f"Error connecting to user's DB: {e}")
    return None

def validate_login(email, password):
    try:
        # Step 1: Fetch user's DB details from master_db
        db_details = get_user_db_details(email, password)
        if not db_details:
            return "no_db_details"  # User found, but no database details were provided
        print("Database details:", db_details)

        # Store `user_domain` in a variable for later use
        user_domain = db_details.get('user_domain', None)

        # Check if db_details contains valid data
        if not all([db_details['db_name'], db_details['db_pwd'], db_details['db_user_name'], db_details['db_server_ip']]):
            return "contact_admin"  # If any required DB detail is missing, return "contact_admin"

        # Step 2: Connect to the user's specific database dynamically
        connection = get_dynamic_db_connection(db_details)
        if not connection:
            return "db_connection_error"  # Unable to connect to the user's DB

        cursor = connection.cursor(dictionary=True)

        # Call the login stored procedure in the user's database
        cursor.callproc('SP_login_screen_v_user_auth', [email, password])

        # Fetch the result
        user = None
        for result in cursor.stored_results():
            user = result.fetchone()

        cursor.close()
        connection.close()

        # If no user is returned from the stored procedure
        if not user:
            return "invalid_credentials"  # Invalid email/password combination

        return user  # Successfully found and authenticated the user

    except mysql.connector.Error as error:
        error_message = str(error)
        if "Error Code: 1644" in error_message:
            return "multiple_users"  # Custom error for multiple users
        elif "Error Code: 1645" in error_message:
            return "no_user"  # Custom error for no matching user
        elif "Error Code: 1646" in error_message:
            return "user_inactive"  # Custom error for inactive user profile
        elif "Error Code: 1647" in error_message:
            return "company_inactive"  # Custom error for inactive company profile
        return "db_error"  # General error for other database issues


@app.route('/login', methods=['POST', 'GET'])
def login():
    global comp_id, br_id
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = validate_login(email, password)
        print("User:", user)

        # Fetch user database details from the master database
        db_details = get_user_db_details(email, password)
        if not db_details:
            flash("User not found or no database details provided. Please contact the administrator.", "warning")
            return render_template("login_page.html")
        

        # Store user domain in the session
        session['user_domain'] = db_details['user_domain']

        # Handle errors returned from `validate_login`
        if user == "no_db_details":
            flash("User found but no database details. Please contact the administrator.", "warning")
        elif user == "contact_admin":
            flash("User not found in the system. Please contact the administrator.", "warning")
        elif user == "db_connection_error":
            flash("Unable to connect to the user's database. Please try again later.", "danger")
        elif user == "invalid_credentials":
            flash("Invalid login credentials. Please try again.", "danger")
        elif user == "multiple_users":
            flash("Multiple users found for the given email and password. Please contact the administrator.", "danger")
        elif user == "no_user":
            flash("No user found for the given email and password. Please try again.", "danger")
        elif user == "company_inactive":
            flash("Company profile is inactive. Please contact the administrator.", "danger")
        elif user == "user_inactive":
            flash("User profile is inactive. Please contact the administrator.", "danger")
        elif user == "db_error":
            flash("A database error occurred. Please try again later.", "danger")
        elif user:
            stored_password_hash = user['user_pwd']
            if stored_password_hash == password:
                # Set session variables
                session['comp_id'] = user['user_comp_id']
                session['br_id'] = user['user_br_id']
                session['user_id'] = user['user_id']
                session['role_id'] = user['role_id']
                session['user_name'] = user['user_name']
                session['email'] = email
                session['password'] = password
                comp_id = user['user_comp_id']
                br_id = user['user_br_id']
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid password. Please try again.", "danger")

    return render_template("login_page.html")


@app.route('/dashboard.html')
def dashboard():
    comp_id = session.get('comp_id')
    br_id = session.get('br_id')

    if not comp_id or not br_id:
        return redirect(url_for('login'))  # Redirect to login if not found in session


    return render_template(
        'dashboard.html'
    )

    # Route to render the login page
@app.route('/')
def index():
    return render_template("login_page.html")

# Route to handle user logout
@app.route('/logout')
def logout():
    #session.clear()s
    return redirect(url_for('/login'))

# ================================================
# MAIN FUNCTION TO RUN THE APP 
# ================================================

if __name__ == '__main__':
    
    socketio.run(app, host = "0.0.0.0", port ="8080", debug=True)