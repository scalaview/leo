from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from flask_login import UserMixin, AnonymousUserMixin
from . import db, login_manager
from sqlalchemy.dialects import mysql
from sqlalchemy import or_, text

class Permission:
    ADMINISTER = 0x01
    ORDER = 0x02
    VIEWHISTORY = 0x03
    EDITORDER = 0x04

class BaseModel(object):
    id = db.Column(db.Integer, primary_key=True)
    createdAt = db.Column(mysql.DATETIME(), nullable=False, default=datetime.now)
    updatedAt = db.Column(mysql.DATETIME(), nullable=False, default=datetime.now, onupdate=datetime.now)



class Role(BaseModel, db.Model):
    __tablename__ = 'roles'
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'Agent': (Permission.ORDER |
                     Permission.VIEWHISTORY, True),
            'Moderator': (Permission.ORDER |
                          Permission.VIEWHISTORY |
                          Permission.EDITORDER, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name

class User(BaseModel, UserMixin, db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    secret_hash = db.Column(db.String(64))
    balance = db.Column(db.Numeric(precision=8, scale=2, asdecimal=False, decimal_return_scale=None), default=0.00)

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.username is not None and self.secret_hash is None:
            self.secret_hash = hashlib.sha1(
                self.username.encode('utf-8')).hexdigest()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id, _external=True),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen
        }
        return json_user

    def __repr__(self):
        return '<User %r>' % self.username

    def is_enough(self, cost):
        if self.balance is not None and self.balance >= cost:
            return True
        else:
            return False

    def reduce_balance(self, cost):
        if self.balance >= cost:
            self.balance = self.balance - cost
            return True
        else:
            return False

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Command(db.Model):
    __tablename__ = 'Commands'
    id = db.Column(db.Integer, primary_key=True)
    namespace = db.Column(db.String(255))
    funName = db.Column(db.String(255))
    argsCode = db.Column(db.String(255))
    state = db.Column(db.Integer, default=0, nullable=False)
    resultCode = db.Column(db.String(255))
    createdAt = db.Column(mysql.DATETIME(), nullable=False, default=datetime.now)
    updatedAt = db.Column(mysql.DATETIME(), nullable=False, default=datetime.now, onupdate=datetime.now)

    STATUS = {
        0: "初始化",
        1: "正在运行",
        2: "运行成功",
        3: "运行失败",
    }

    @staticmethod
    def state_name(state):
        return Command.STATUS.get(state, "运行失败")


class SequelizeMeta(db.Model):
    __tablename__ = 'SequelizeMeta'
    name = db.Column(db.String(255), primary_key=True, nullable=False, unique=True)


class OperationRecord(BaseModel, db.Model):
    __tablename__ = 'operation_records'
    model_type = db.Column(db.String(32), nullable=False)
    model_type_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    operation_type = db.Column(db.String(32))
    operation_type_value = db.Column(db.String(32))

    @property
    def target(self):
        if self.model_type == 'Commands':
            return Command.query.get(self.model_type_id)
        elif self.model_type == 'orders':
            return Order.query.join(OperationRecord, OperationRecord.model_type_id == self.model_type_id)\
                .filter(OperationRecord.model_type == "orders").first()

    @property
    def user(self):
        if self.id is not None:
            return User.query.filter_by(id=self.user_id).first()

    @staticmethod
    def user_records(types, user_id):
        or_filters = [text("model_type='%s'"%type) for type in types]
        return OperationRecord.query.filter(or_(*or_filters)).filter_by(user_id=user_id)

    @staticmethod
    def can_do(operation_type, operation_type_value, namespace):
        return not Command.query.join(OperationRecord, OperationRecord.model_type_id == Command.id)\
            .filter(OperationRecord.model_type == "Commands")\
            .filter(OperationRecord.operation_type == operation_type)\
            .filter(OperationRecord.operation_type_value == operation_type_value)\
            .filter(Command.namespace == namespace)\
            .filter(text("DATE_ADD(Commands.createdAt, INTERVAL 1 MINUTE) > NOW()"))\
            .order_by(Command.createdAt.desc())\
            .all()


class Product(BaseModel, db.Model):
    __tablename__ = 'products'
    name = db.Column(db.String(255))
    code = db.Column(db.String(64), unique=True, nullable=False)
    price = db.Column(db.Numeric(precision=8, scale=2, asdecimal=False, decimal_return_scale=None), default=0.00)
    purchase_price = db.Column(db.Numeric(precision=8, scale=2, asdecimal=False, decimal_return_scale=None) , default=0.00)
    order_items = db.relationship('OrderItem', backref='product', lazy='dynamic')

    @staticmethod
    def insert_products():
        product = Product(name="南方Plus-问答移动200M", code="souPlus-11-200M")
        db.session.add(product)
        db.session.commit()

class OrderState(object):
    INIT = (0, "init")
    RUNNING = (1, "runnint")
    SUCCESS = (2, "success")
    FAIL = (3, "fail")
    REFUND = (4, "refund")


class Order(BaseModel, db.Model):
    __tablename__ = 'orders'
    total = db.Column(db.Numeric(precision=8, scale=2, asdecimal=False, decimal_return_scale=None), default=0.00)
    cost = db.Column(db.Numeric(precision=8, scale=2, asdecimal=False, decimal_return_scale=None), default=0.00)
    items = db.relationship('OrderItem', backref='order', lazy='dynamic')
    state = db.Column(db.Integer, nullable=False, default=0)
    phone = db.Column(db.String(255))

    def calculate_total(self):
        if self.items.count() > 0:
            self.total = 0
            self.cost = 0
            for item in self.items.all():
                self.total = self.total + item.get_product.price
                self.cost = self.cost + item.get_product.purchase_price
        return self.total


class OrderItem(BaseModel, db.Model):
    __tablename__ = 'order_items'
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)

    @property
    def get_product(self):
        return Product.query.get(self.product_id)
