from flask import Flask, render_template, request, redirect, url_for, session, flash, after_this_request
from werkzeug.security import generate_password_hash, check_password_hash
import os
from cryptography.fernet import Fernet
import os
import time
from threading import Thread

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Mock database for users and files
data_folder = 'data_folder'  # Folder where text files are stored
users = {}
files = {}  # Stores file-specific access times {filename: access_time_in_seconds}

# A global dictionary to store user access info (username and file access)
user_access = {}

# A global dictionary to store temporary file contents for each user session
temp_file_content = {}

# Ensure the data folder exists
os.makedirs(data_folder, exist_ok=True)

# Timer threads to manage file access and remove file content from memory after expiration
def auto_close_file(username, duration):
    time.sleep(duration)
    temp_file_content.pop(username, None)
    user_access.pop(username, None)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('user_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/user/dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        filename = request.form['filename']
        if filename in files:
            user_access[session['username']] = filename
            duration = files[filename]
            # Read file content and store it in a temporary variable for the user
            file_path = os.path.join(data_folder, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                temp_file_content[session['username']] = content  # Store in temp variable
                # Start a background thread to remove file after the specified time
                thread = Thread(target=auto_close_file, args=(session['username'], duration))
                thread.start()
                flash(f"You have {duration} seconds to view '{filename}'.", 'success')
                return redirect(url_for('view_file', filename=filename))
            flash('File not found.', 'danger')

    file_list = os.listdir(data_folder)
    return render_template('user_dashboard.html', files=file_list)

@app.route('/view/<filename>')
def view_file(filename):
    if session['username'] not in user_access or user_access[session['username']] != filename:
        flash('Unauthorized access or file session expired.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Retrieve the temporary file content for the user
    content = temp_file_content.get(session['username'])
    if content:
        @after_this_request
        def redirect_after_expiration(response):
            # Set a timer to redirect after the specified duration
            duration = files.get(filename, 0)
            #time.sleep(duration)  # Wait for the file session duration to expire
            response.headers["Refresh"] = f"{duration}; url={url_for('home')}"  # Redirect after timeout
            return response

        return render_template('view_file.html', filename=filename, content=content)

    flash('File not found or session expired.', 'danger')
    return redirect(url_for('user_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'adm' and password == 'adm':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        filename = request.form['filename']
        access_time = int(request.form['access_time'])
        files[filename] = access_time
        flash(f"Access time set for '{filename}' to {access_time} seconds.", 'success')

    file_list = os.listdir(data_folder)
    return render_template('admin_dashboard.html', files=file_list, access_times=files)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists!', 'danger')
        else:
            users[username] = generate_password_hash(password)
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)

