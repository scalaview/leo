from flask import render_template, redirect, request, url_for, flash, jsonify, current_app
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import admin
from .. import db
from ..models import Permission, Role, User, OperationRecord, Command, Product\
        ,OrderState, Order, OrderItem
from .forms import LoginForm, RegistrationForm, SouPlusForm#, ChangePasswordForm,\
#     PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from sqlalchemy import or_, text
from flask_sqlalchemy import get_debug_queries

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

@admin.route('/souplus_11_give', methods=['GET', 'POST'])
@login_required
def order():
    form = SouPlusForm()

    if form.validate_on_submit():
        if OperationRecord.can_do("order", form.phone.data, "souPlus"):
            command = Command(namespace="souPlus", funName="gift",\
                argsCode="11, %s, %s"%(form.phone.data, form.vertify.data) )
            db.session.add(command)
            db.session.commit()

            record = OperationRecord(model_type="Commands", model_type_id=command.id,\
                user_id=current_user.get_id(), operation_type="order", operation_type_value=form.phone.data)
            product = Product.query.filter_by(code="souPlus-11-200M").first_or_404()
            order = Order(state=OrderState.INIT[0])
            item = OrderItem(product_id=product.id)
            order.items.append(item)
            order.calculate_total()
            db.session.add(record)
            db.session.add(item)
            db.session.add(order)
            db.session.commit()
    return render_template('admin/order.html', form=form)


@admin.route('/souplus_records', methods=['GET'])
@login_required
def souplus_records():
    page = request.args.get("page", 1, int)
    types = request.args.get("types", ['orders', 'Commands'])
    or_filters = [text("operation_records.model_type='%s'"%type) for type in types]
    pagination = OperationRecord.query.join(Command, Command.id == OperationRecord.model_type_id)\
                    .filter(OperationRecord.model_type == "Commands")\
                    .filter(or_(OperationRecord.operation_type == "order", OperationRecord.operation_type == "phone"))\
                    .filter(or_(*or_filters)).filter(OperationRecord.user_id == current_user.get_id())\
                    .filter(Command.namespace == "souPlus")\
                    .order_by(OperationRecord.createdAt.desc())\
                    .paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
                        error_out=False)
    records = pagination.items
    result = []
    for item in records:
        term = item.target
        if term is not None:
            result.append({
                    'phone': item.operation_type_value,
                    'msg': Command.state_name(term.state)
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
        if OperationRecord.can_do("phone", form.phone.data, "souPlus"):
            command = Command(namespace="souPlus", funName="getCode",\
                argsCode="11, %s"%form.phone.data)
            db.session.add(command)
            db.session.commit()

            record = OperationRecord(model_type="Commands", model_type_id=command.id,\
                user_id=current_user.get_id(), operation_type="phone", operation_type_value=form.phone.data)
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


@admin.after_app_request
def after_request(response):
    for query in get_debug_queries():
        print('query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'%(query.statement,\
            query.parameters, query.duration,\
            query.context))
        return response
