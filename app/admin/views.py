from flask import render_template, redirect, request, url_for, flash,\
    jsonify, current_app, abort
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import admin
from .. import db
from ..models import Permission, Role, User, OperationRecord, Command, Product\
        ,OrderState, Order, OrderItem
from .forms import LoginForm, RegistrationForm, SouPlusForm,\
    BalanceForm#, ChangePasswordForm,\
#     PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from sqlalchemy import or_, text
from flask_sqlalchemy import get_debug_queries

@admin.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()

@admin.errorhandler(401)
def custom_401(error):
    if not current_user.is_authenticated:
        flash("login first")
        return redirect(url_for("admin.login"))
    else:
        flash("permission deny")
        return redirect(url_for("admin.index"))


@admin.errorhandler(404)
def custom_404(error):
    return render_template('admin/404.html'), 404

def can_do(permission):
    if not current_user.is_authenticated:
        abort(401)
    elif current_user.is_administrator():
        return True
    elif current_user.can(permission):
        return True
    else:
        abort(401)

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
    return render_template('admin/index.html')


@admin.route('/register', methods=['GET', 'POST'])
def register():
    count = User.query.count()
    if count == 0 or (current_user.is_authenticated and current_user.is_administrator()):
        form = RegistrationForm()
        if form.validate_on_submit():
            user = User(username=form.username.data,
                        password=form.password.data)
            role = Role.query.filter_by(name="Agent").first()
            user.role = role
            db.session.add(user)
            db.session.commit()
            flash("create user success")
            if count == 0:
                return redirect(url_for('admin.login'))
        return render_template('admin/register.html', form=form)
    else:
        flash("Permission deny")
        return redirect(url_for('admin.index'))

@admin.route('/souplus_eleven_give', methods=['GET', 'POST'])
@login_required
def souplus_eleven_give():
    can_do(Permission.ORDER)
    form = SouPlusForm()

    if form.validate_on_submit():
        product = Product.query.filter_by(code="souPlus-11-200M").first_or_404()

        if OperationRecord.can_do("order", form.phone.data, "souPlus"):
            order = Order(state=OrderState.INIT[0], phone=form.phone.data,\
                user_id=current_user.get_id())
            item = OrderItem(product_id=product.id)
            order.items.append(item)
            total = order.calculate_total()

            if not current_user.is_enough(total):
                flash("余额不足，请充值")
            elif current_user.reduce_balance(total):
                db.session.add(current_user)
                db.session.add(item)
                db.session.add(order)
                db.session.commit()

                command = Command(namespace="souPlus", funName="gift",\
                    argsCode="11, %s, %s"%(form.phone.data, form.vertify.data) )
                db.session.add(command)
                db.session.commit()

                record = OperationRecord(model_type="Commands", model_type_id=command.id,\
                    user_id=current_user.get_id(), operation_type="order", operation_type_value=order.id)
                db.session.add(record)
                db.session.commit()
                flash("操作成功")
        else:
            flash("操作过于频繁")
    return render_template('admin/order.html', form=form)

@admin.route('/souplus_records', methods=['GET'])
@login_required
def souplus_records():
    can_do(Permission.VIEWHISTORY)

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
            if item.operation_type == "order":
                order = Order.query.get(item.operation_type_value)
                if order is not None:
                    phone = order.phone
                else:
                    phone = item.operation_type_value
            else:
                phone = item.operation_type_value
            result.append({
                    'phone': phone,
                    'msg': Command.state_name(term.state)
                })

    return jsonify({
            'next': "",
            'items': result
        })

@admin.route('/souplus_send_code', methods=['POST'])
def souplus_send_code():
    can_do(Permission.ORDER)
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


@admin.route('/user/<id>', methods=['GET', 'POST'])
def user(id):
    can_do(Permission.ADMINISTER)
    form = BalanceForm()
    user = User.query.get(id)
    form.balance.data = user.balance
    if form.validate_on_submit():
        user.balance = form.balance.data
        db.session.add(user)
        db.session.commit()
        flash("update success")
    return render_template('admin/user.html', form=form)


@admin.route('/users', methods=['GET'])
def users():
    can_do(Permission.ADMINISTER)
    page = request.args.get("page", 1, int)
    pagination = User.query.filter(User.id != current_user.id).order_by(User.last_seen.desc())\
        .paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
    users = pagination.items
    return render_template('admin/users.html', users=users, pagination=pagination)

@admin.route('/orders', methods=['GET'])
@login_required
def orders():
    page = request.args.get("page", 1, int)
    pagination = current_user.orders().order_by(Order.updatedAt.desc())\
        .paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
    orders = pagination.items
    return render_template('admin/orders.html', orders=orders, pagination=pagination)

@admin.route('/allorders', methods=['GET'])
@login_required
def allorders():
    can_do(Permission.ADMINISTER)
    page = request.args.get("page", 1, int)
    pagination = Order.query.order_by(Order.updatedAt.desc())\
        .paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
    orders = pagination.items
    return render_template('admin/orders.html', orders=orders, pagination=pagination)

