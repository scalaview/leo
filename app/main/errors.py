from . import main
from flask import render_template


@main.errorhandler(404)
def custom_404(error):
    return render_template('admin/404.html'), 404

@main.errorhandler(500)
def custom_500(error):
    return render_template('admin/500.html'), 500