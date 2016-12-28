from . import main
from flask import render_template


@main.errorhandler(404)
def custom_404(error):
    return render_template('admin/404.html'), 404