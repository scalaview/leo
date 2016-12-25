from flask_wtf import FlaskForm as Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField,\
    FloatField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo,\
    NumberRange
from wtforms import ValidationError
from ..models import User


class BaseForm(Form):
    class Meta:
        def bind_field(self, form, unbound_field, options):
            filters = unbound_field.kwargs.get('filters', [])
            filters.append(my_strip_filter)
            return unbound_field.bind(form=form, filters=filters, **options)

def my_strip_filter(value):
    if value is not None and hasattr(value, 'strip'):
        return value.strip()
    return value

class LoginForm(Form):
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class SouPlusForm(BaseForm):
    phone = StringField('phone', validators=[
        Required(), Length(11), Regexp('[0-9]*$', 0,
                                          'Phone must have only numbers')])
    vertify = StringField('vertify', validators=[
        Required(), Length(6), Regexp('[A-Za-z0-9]*$', 0,
                                          'vertify must have only letters, '
                                          'numbers')])
    submit = SubmitField('Submit')

class BalanceForm(BaseForm):
    balance = FloatField('balance', validators=[
        Required(), NumberRange(min=0, message="must greater than 0")])
    submit = SubmitField('Submit')

