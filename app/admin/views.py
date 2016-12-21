from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import admin
from .. import db
from ..models import Permission, Role, User
from .forms import LoginForm, RegistrationForm, SouPlusForm#, ChangePasswordForm,\
#     PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm

@admin.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('admin.index'))
        flash('Invalid username or password.')
    return render_template('admin/login.html', form=form)


@admin.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('admin.login'))


@admin.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if current_user.can(Permission.VIEWHISTORY) and \
            form.validate_on_submit():
        return redirect(url_for('.index'))
    return render_template('admin/index.html')


@admin.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('admin.login'))
    return render_template('admin/register.html', form=form)

@admin.route('/order', methods=['GET', 'POST'])
def order():
    form = SouPlusForm()
    if form.validate_on_submit(): #and \
           # form.validate_on_submit():
        pass
    return render_template('admin/order.html', form=form)