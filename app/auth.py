import secrets
import os
from flask import render_template, url_for, flash, redirect, request, Blueprint, make_response
from app import app, bcrypt, db, login_manager, mail
from app.models import User, ExamRegistration
from flask_mail import Message
from app.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, UpdateAccountForm, ExamRegistrationForm, UpdateExamRegistrationForm
from flask_login import login_user, login_required, current_user
import random, copy
from app.lowe_primary_questions import original_questions
from app.upper_primary_questions import upper_questions
import pdfkit
from datetime import date

today = date.today()


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('homepage'))
        else:
            flash(f'Invalid Credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('user/login.html', title='Login', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(fullname=form.fullname.data, email=form.email.data, password=hashed_password, contact_no=form.contact_no.data, gender=form.gender.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Registration Successfull for {user.email}', 'success')
        return redirect(url_for('login'))
    return render_template('user/Registration.html', title='Sign up', form=form)


@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash(f'You must be logged in to view that page.', 'danger')
    return redirect(url_for('login'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link :
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.!!
'''
    mail.send(msg)


@app.route('/reset_password', methods=('GET', 'POST'))
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))  # Bypass if user is logged in
    error = None
    message = None
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash(f'An email has been sent with instruction to reset your password', 'success')
        return redirect(url_for('login'))
    return render_template('user/forgot.html', form=form, error=error, message=message)


@app.route('/reset_password/<token>', methods=('GET', 'POST'))
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))  # Bypass if user is logged in
    user = User.verify_reset_token(token)
    if user is None:
        flash(f'That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been Updated', 'success')
        return redirect(url_for('login'))
    return render_template('forgot/password_reset.html', form=form)


@app.route('/account', methods=('GET', 'POST'))
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.fullname = form.fullname.data
        current_user.email = form.email.data
        current_user.contact_no = form.contact_no.data
        db.session.commit()
        flash(f'Your Account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.fullname.data = current_user.fullname
        form.email.data = current_user.email
        form.contact_no.data = current_user.contact_no
    return render_template('user/account.html', title='Account',
                           form=form)


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/user_documents', picture_fn)
    form_picture.save(picture_path)
    return picture_fn


@app.route('/exam_registration', methods=('GET', 'POST'))
@login_required
def exam_registration():
    form = ExamRegistrationForm()
    if current_user.e_r_s is None:
        if form.validate_on_submit():
            if form.documents.data:
                picture_file = save_picture(form.documents.data)
                aadhaardoc = save_picture(form.aadhaar.data)
                user_exam_registration_data = ExamRegistration(fullname=form.fullname.data, email=form.email.data,
                                                           contact_no=form.contact_no.data, gender=form.gender.data,
                                                           dateofbirth=form.dateofbirth.data, address=form.address.data,
                                                           city=form.city.data, pincode=form.pincode.data,
                                                           state=form.state.data, country=form.country.data,
                                                           qualifications=form.qualifications.data, category=form.category.data,aadhaar=aadhaardoc , documents=picture_file,
                                                           user_id=current_user.id)
                current_user.e_r_s = 'Yes'
                db.session.add(user_exam_registration_data)
                db.session.commit()
                flash(f'Exam Registration Form Submitted!!', 'success')
                return redirect(url_for('account'))
        return render_template('user/ExamRegistration.html', form=form)
    else:
        flash(f'You have submitted Exam Registration Form Previously!', 'info')
        return render_template('user/exam_registration_error.html')


@app.route('/Update_exam_registration/<int:e_r_f_id>', methods=('GET', 'POST'))
@login_required
def Update_exam_registration(e_r_f_id):
    form = UpdateExamRegistrationForm()
    e_r_data = ExamRegistration.query.get(e_r_f_id)
    if form.validate_on_submit():
        picture_file = save_picture(form.documents.data)
        aadhaardoc = save_picture(form.aadhaar.data)
        e_r_data.gender = form.gender.data
        e_r_data.dateofbirth = form.dateofbirth.data
        e_r_data.address = form.address.data
        e_r_data.city = form.city.data
        e_r_data.pincode = form.pincode.data
        e_r_data.state = form.state.data
        e_r_data.country = form.country.data
        e_r_data.qualifications = form.qualifications.data
        e_r_data.aadhaar = aadhaardoc
        e_r_data.documents = picture_file
        db.session.commit()
        flash(f'You have updated Exam Registration Form successfully!', 'success')
    elif request.method == 'GET':
        form.gender.data = e_r_data.gender
        form.dateofbirth.data = e_r_data.dateofbirth
        form.address.data = e_r_data.address
        form.city.data = e_r_data.city
        form.pincode.data = e_r_data.pincode
        form.state.data = e_r_data.state
        form.country.data = e_r_data.country
        form.qualifications.data = e_r_data.qualifications
        form.category.data = e_r_data.category
    return render_template('user/UpdateExamRegistration.html', title=f'Update Exam Regisration Form {e_r_f_id}', form=form)


def shuffle(q):
    selected_keys = []
    i = 0
    while i < len(q):
        current_selection = random.choice(list(q.keys()))
        if current_selection not in selected_keys:
            selected_keys.append(current_selection)
            i = i + 1
    return selected_keys


@app.route('/quiz')
@login_required
def quiz():
    e_r_d = ExamRegistration.query.filter_by(user_id=current_user.id).first()
    if e_r_d.category == 'lowerprimary(1-5)':
        questions = copy.deepcopy(original_questions)
    else:
        questions = copy.deepcopy(upper_questions)
    questions_shuffled = shuffle(questions)
    for i in questions.keys():
        random.shuffle(questions[i])
    return render_template('user/quiz.html', q=questions_shuffled, o=questions)


@app.route('/an', methods=['GET', 'POST'])
@login_required
def quiz_answers():
    e_r_d = ExamRegistration.query.filter_by(user_id=current_user.id).first()
    if e_r_d.category == 'lowerprimary(1-5)':
        questions = copy.deepcopy(original_questions)
    else:
        questions = copy.deepcopy(upper_questions)
    current_user.e_t_s = 'Yes'
    db.session.commit()
    correct = 0
    if e_r_d.category == 'lowerprimary(1-5)':
        for i in questions.keys():
            answered = request.form[i]
            if original_questions[i][0] == answered:
                correct = correct + 1
                current_user.score = correct*2
                db.session.commit()
    else:
        for i in questions.keys():
            answered = request.form[i]
            if upper_questions[i][0] == answered:
                correct = correct + 1
                current_user.score = correct*2
                db.session.commit()
    if correct <= 8:
        flash(r'You are failed in this Test, Your Score is :' + str(correct*2), 'danger')
        return render_template('user/failed.html')
    else:
        flash(r'Congratulation, You have successfully completed exam test, Your Score is :' + str(correct*2), 'success')
        return render_template('user/Test_Done.html')


@app.route('/ready_certificate')
@login_required
def ready_certificate():
    return render_template('user/Test_Done.html')


@app.route('/exam_test/<int:user_id>', methods=('GET', 'POST'))
@login_required
def exam_test(user_id):
    if current_user.e_r_s is None:
        flash(f'You have to first submit Exam Registration Form', 'danger')
        return render_template('user/examregistration_notdone.html')
    else:
        if current_user.e_d is None:
            flash(f'You Submitted ExamRegistration Form is under review by our Executive , Once it is approved You are able to do a test ', 'danger')
            return render_template('user/examregistration_notdone.html')
        else:
            e_r_d = ExamRegistration.query.filter_by(user_id=user_id).first()
            if current_user.e_t_s is None:
                if e_r_d.category == 'lowerprimary(1-5)':
                    return redirect(url_for('quiz'))
                else:
                    if e_r_d.category == 'upperprimary(6-10)':
                        return redirect(url_for('quiz'))
                    else:
                        if e_r_d.category == 'secondary(11-12)':
                            pass
            else:
                flash(f'You have given your test previously!', 'info')
                return render_template('user/exam_test_error.html')


@app.route('/clear')
@login_required
def clear():
    current_user.e_t_s = ''
    db.session.commit()
    return 'Done'


@app.route('/start_exam')
@login_required
def start_exam():
    return render_template('user/StartExam.html')


@app.route('/certificate')
@login_required
def certificate():
    d1 = today.strftime("%d/%m/%Y")
    user = ExamRegistration.query.filter_by(user_id=current_user.id).first()
    category = user.category
    rendered = render_template('user/pdf_template.html', date=d1, ct=category)
    pdf = pdfkit.from_string(rendered, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=output.pdf '

    return response


@app.route('/homepage')
@login_required
def homepage():
    return render_template('homepage.html')








