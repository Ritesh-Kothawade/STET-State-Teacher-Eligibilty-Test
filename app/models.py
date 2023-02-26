from app import db, login_manager, app
from datetime import datetime
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(220),  nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    contact_no = db.Column(db.Integer, unique=True, nullable=False)
    gender = db.Column(db.String(60))
    e_r_s = db.Column(db.String)
    e_t_s = db.Column(db.String)
    score = db.Column(db.Integer)
    e_d = db.Column(db.String)

    def get_reset_token(self, expire_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expire_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        extend_existing = True
        return f'User({self.fullname},{self.email},{self.contact_no},{self.gender},{self.e_r_s},{self.id},{self.e_r_s})'


class ExamRegistration(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(220), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contact_no = db.Column(db.Integer, unique=True, nullable=False)
    gender = db.Column(db.String(60))
    dateofbirth = db.Column(db.Date, nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String, nullable=False)
    pincode = db.Column(db.Integer, nullable=False)
    state = db.Column(db.String, nullable=False)
    country = db.Column(db.String, nullable=False)
    qualifications = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    aadhaar = db.Column(db.String, nullable=False)
    documents = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        extend_existing = True
        return f'ExamRegistration({self.fullname},{self.email},{self.contact_no},{self.gender},{self.dateofbirth},{self.address},{self.city},{self.pincode},{self.state},{self.country},{self.qualifications},{self.documents},{self.user_id})'


class Admins(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        extend_existing = True
        return f'Admin({self.id},{self.email},{self.password})'
