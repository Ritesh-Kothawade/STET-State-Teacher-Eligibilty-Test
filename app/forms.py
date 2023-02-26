from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms.fields import StringField, PasswordField, SubmitField, IntegerField, SelectField, RadioField, DateField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, InputRequired
from app.models import User, ExamRegistration
from flask_login import current_user


class RegistrationForm(FlaskForm):
    fullname = StringField('Fullname', validators=[DataRequired(), Length(min=5, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm_Password', validators=[DataRequired(), EqualTo('password')])
    contact_no = IntegerField('Contact_no', validators=[DataRequired()])
    gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('!!Invalid Email!!')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Something Went Wrong!')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm_Password', validators=[DataRequired(), EqualTo('password')])


class UpdateAccountForm(FlaskForm):
    fullname = StringField('Fullname', validators=[DataRequired(), Length(min=5, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_no = IntegerField('Contact_no', validators=[DataRequired()])

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user is None:
                raise ValidationError('Something Went Wrong!')


class ExamRegistrationForm(FlaskForm):
    fullname = StringField('Fullname', validators=[DataRequired(), Length(min=5, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_no = IntegerField('Contact_no', validators=[DataRequired()])
    gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')])
    dateofbirth = DateField('DatePicker', format='%d-%m-%Y')
    address = TextAreaField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    pincode = IntegerField('Pin Code', validators=[DataRequired()])
    state = StringField('State', default='Maharashtra', validators=[DataRequired()])
    country = StringField('Country', default='India', validators=[DataRequired()])
    qualifications = SelectField('Qualifications', choices=[
        ('high school(10th)', 'High School(10th)'),
        ('high school(12th)', 'Higher School(12th)'),
        ('graduation(bachelors)', 'Graduation(Bachelors)'),
        ('post graduation(masters)', 'Post Graduation(Masters)'),
        ('phd', 'Phd')
    ])
    category = RadioField('Apply For', choices=[('lowerprimary(1-5)', 'Lower Primary(1-5)'),
                                                ('upperprimary(6-10)', 'Upper Primary(6-10)')])
    aadhaar = FileField('Upload Aadhaar Card', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf']), DataRequired()])
    documents = FileField('Upload Documents', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf']), DataRequired()])
    submit = SubmitField('Submit')


class UpdateExamRegistrationForm(FlaskForm):
    fullname = StringField('Fullname', validators=[DataRequired(), Length(min=5, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_no = IntegerField('Contact_no', validators=[DataRequired(), InputRequired()])
    gender = RadioField('Gender', choices=[('male', 'Male'), ('female', 'Female')])
    dateofbirth = DateField('DatePicker', format='%d-%m-%Y')
    address = TextAreaField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    pincode = IntegerField('Pin Code', validators=[DataRequired()])
    state = StringField('State', default='Maharashtra', validators=[DataRequired()])
    country = StringField('Country', default='India', validators=[DataRequired()])
    qualifications = SelectField('Qualifications', choices=[
        ('high school(10th)', 'High School(10th)'),
        ('high school(12th)', 'Higher School(12th)'),
        ('graduation(bachelors)', 'Graduation(Bachelors)'),
        ('post graduation(masters)', 'Post Graduation(Masters)'),
        ('phd', 'Phd')
    ])
    category = RadioField('Apply For', choices=[('lowerprimary(1-5)', 'Lower Primary(1-5)'), ('upperprimary(6-10)', 'Upper Primary(6-10)')])
    aadhaar = FileField('Upload Aadhaar Card', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf']), DataRequired()])
    documents = FileField('Upload Documents', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf']), DataRequired()])
    submit = SubmitField('Submit')


class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


