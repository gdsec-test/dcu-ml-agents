from flask import Flask
from flask_restplus import Api
from .api import api as ns1


def create_app(config):
    app = Flask(__name__)
    app.config.SWAGGER_UI_JSONEDITOR = True
    app.config.SWAGGER_UI_DOC_EXPANSION = 'list'
    api = Api(
        app,
        version='1.0',
        title='DCU ML Agents',
        description='Machine Learning Models to provide real time predictions.',
        doc='/doc'
    )
    api.add_namespace(ns1)
    return app
