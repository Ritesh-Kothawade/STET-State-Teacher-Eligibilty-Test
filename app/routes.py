from flask import render_template, url_for, flash, redirect, request, Blueprint
from app import app, bcrypt, db, login_manager
from app.models import User, Admins, ExamRegistration
from app.forms import RegistrationForm, LoginForm, AdminLoginForm
from flask_login import login_user, login_required, current_user,  logout_user
from app import admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
import os.path as op


@app.route('/')
@app.route('/base')
def base():
    return render_template('base.html')


@app.route('/user_dashboard', methods=['GET'])
@login_required
def user_dashboard():
    """Serve logged-in Dashboard."""
    return render_template('user/user_dashboard.html', title='Dashboard', template='dashboard-template', current_user=current_user, body="You are now logged in!")


@app.route("/logout")
@login_required
def logout():
    """User log-out logic."""
    logout_user()
    flash(f'You have been Logged Out!!', 'success')
    return redirect(url_for('login'))


@app.route('/eligibility')
def eligibility():
    return render_template('eligibility.html')


@app.route('/syllabus')
def syllabus():
    return render_template('base/Syllabus.html')


@app.route('/previous_question_papers')
def previous_question_papers():
    return render_template('base/Previous_Question_Papers.html')


@app.route('/flow_diagram')
def flow_diagram():
    return render_template('flow_diagram.html')


@app.route('/old_papers')
def old_papers():
    return render_template('base/Old_Papers.html')


@app.route('/contact')
def contact():
    return render_template('base/contact.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admins.query.filter_by(email=form.email.data).first()
        if form.email.data == admin.email and form.password.data == admin.password:
            return redirect('/admin')
        else:
            flash(f'Invalid Credentials', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin/Admin_Login.html', title='Admin_Login', form=form)


@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin/Admin_dashboard.html')


@app.route("/admin_logout")
def admin_logout():
    flash(f'You have been Logged Out!!', 'success')
    return redirect(url_for('admin_login'))


path = op.join(op.dirname(__file__), 'static/user_documents')

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(ExamRegistration, db.session))
admin.add_view(FileAdmin(path, name='User Documents'))
admin.add_view(ModelView(Admins, db.session))


@app.route("/?utm_source=android_app")
def test_app():
    return print("Hello")

