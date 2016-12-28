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
    username = StringField('用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          '用户名只能包含大小写字母, '
                                          '数字、点和下划线')])
    password = PasswordField('密 码', validators=[Required()])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登 录')


class RegistrationForm(Form):
    username = StringField('用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          '用户名只能包含大小写字母,  '
                                          '数字、点和下划线')])
    password = PasswordField('密 码', validators=[
        Required(), EqualTo('password2', message='两次输入的密码必须一致')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('注 册')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已经存在')

class SouPlusForm(BaseForm):
    phone = StringField('手机号码', validators=[
        Required(), Length(11), Regexp('[0-9]*$', 0,
                                          '手机只能是11位数字')])
    vertify = StringField('验证码', validators=[
        Required(), Length(6), Regexp('[A-Za-z0-9]*$', 0,
                                          '验证码只能是大小写字母, '
                                          '数字')])
    submit = SubmitField('提 交')

class BalanceForm(BaseForm):
    balance = FloatField('余 额', validators=[
        Required(), NumberRange(min=0, message="必须大于0")])
    submit = SubmitField('提 交')

