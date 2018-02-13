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
#    app.config['CELERY_BROKER_URL'] = 'amqp://art:hVhRU8cNPAnpaBy4@localhost/art'
 #   app.config['CELERY_RESULT_BACKEND'] = 'amqp://art:hVhRU8cNPAnpaBy4@localhost/art'

#    celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
#    celery.conf.update(app.config)

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

    return app
