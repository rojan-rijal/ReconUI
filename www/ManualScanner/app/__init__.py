# app/__init__.py

# third-party imports
from flask import Flask, render_template, send_file
from flask_bootstrap import Bootstrap
from celery import Celery

# local imports
from config import app_config

# db variable initialization

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config["production"])
    app.config.from_pyfile('config.py')
    Bootstrap(app)

    from .home import home as home_blueprint
    app.register_blueprint(home_blueprint)
    
    @app.errorhandler(404)
    def page_not_found(e):
	return render_template('error.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
	return render_template('error.html'), 500

    @app.route("/robots.txt")
    def robots_txt():
	return send_file('/var/www/ManualScanner/app/templates/robots.txt', attachment_filename='robots.txt')

    @app.route('/credits', methods=['GET'])
    def give_credits():
        return render_template('home/credits.html')

    @app.route('/security', methods=['GET'])
    def security_report():
	return render_template('vulnerability.html')

    @app.route('/agreement', methods=['GET'])
    def agreement():
	return render_template('terms.html')

    return app
