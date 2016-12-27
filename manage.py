#!/usr/bin/env python
import os

if os.path.exists('.env'):
    print('Importing environment from .env...')
    for line in open('.env'):
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1]

from app import create_app, db
from app.models import User, Role, Permission, Command, OperationRecord, Command,\
    Product, OrderState, Order, OrderItem
from app.admin.forms import LoginForm, RegistrationForm, SouPlusForm
from flask_script import Manager, Shell, Server
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import get_debug_queries

app = create_app(os.getenv('LEO_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(get_debug_queries=get_debug_queries, app=app, db=db, User=User, Role=Role, \
        Product=Product, Permission=Permission, Command=Command, OperationRecord=OperationRecord, \
        OrderItem=OrderItem, Order=Order, OrderState=OrderState,\
        LoginForm=LoginForm, RegistrationForm=RegistrationForm, SouPlusForm=SouPlusForm)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)
manager.add_command('runserver', Server(host='localhost', port='4040'))


@manager.command
def profile(length=25, profile_dir=None):
    """Start the application under the code profiler."""
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length],
                                      profile_dir=profile_dir)
    app.run()


@manager.command
def deploy():
    """Run deployment tasks."""
    from flask_migrate import upgrade
    from app.models import Role, User

    # migrate database to latest revision
    # upgrade()



if __name__ == '__main__':
    manager.run()
