from flask import render_template, redirect, request, url_for, flash, jsonify, current_app
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import admin
from .. import db
from ..models import Permission, Role, User, OperationRecord, Command
from .forms import LoginForm, RegistrationForm, SouPlusForm#, ChangePasswordForm,\
#     PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from sqlalchemy import or_, text


@admin.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()


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
@login_required
def order():
    form = SouPlusForm()
    if form.validate_on_submit(): #and \
           # form.validate_on_submit():
        pass
    return render_template('admin/order.html', form=form)


@admin.route('/souplus_records', methods=['GET'])
@login_required
def souplus_records():
    types = request.args.get("types", ['orders', 'Commands'])
    page = request.args.get("page", 1, int)
    or_filters = [text("operation_records.model_type='%s'"%type) for type in types]
    pagination = OperationRecord.query.join(Command, Command.id == OperationRecord.model_type_id)\
                    .filter(OperationRecord.model_type == "Commands")\
                    .filter(or_(*or_filters)).filter(OperationRecord.user_id == current_user.get_id())\
                    .filter(Command.namespace == "souPlus")\
                    .order_by(OperationRecord.createdAt)\
                    .paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                        error_out=False)
    records = pagination.items
    result = []
    for item in records:
        term = item.target()
        if term is not None:
            result.append({
                    phone: term.argsCode.split(',')[0],
                    msg: Command.state_name(term.state)
                })

    return jsonify({
            'next': "",
            'items': result
        })

@admin.route('/souplus_send_code', methods=['POST'])
def souplus_send_code():
    form = SouPlusForm()
    form.phone.data = request.form.get("phone")
    form.validate()
    if not form.phone.errors:
        print(OperationRecord.can_do())
        if OperationRecord.can_do():
            command = Command(namespace="souPlus", funName="getCode",\
                argsCode="11, %s"%form.phone.data)
            db.session.add(command)
            db.session.commit()

            record = OperationRecord(model_type="Commands", model_type_id=command.id,\
                user_id=current_user.get_id())
            db.session.add(record)
            db.session.commit()
            return jsonify({
                'err': 0,
                'msg': "短信已提交"
            })
        else:
            return jsonify({
                'err': 1,
                'msg': "请求过于频繁"
            })
    else:
        return jsonify({
            'err': 1,
            'msg': form.phone.errors[0]
        })
