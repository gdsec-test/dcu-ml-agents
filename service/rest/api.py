from flask import request
from flask_restplus import Namespace, Resource
from service.utils.malicious_url_model import MaliciousUrlModel

api = Namespace('v1', title='DCU ML Agents', description='')
model = MaliciousUrlModel()


@api.route('/health', endpoint='health')
class Health(Resource):
    @api.response(200, 'OK')
    def get(self):
        """
        Health check endpoint
        """
        return 'OK', 200


@api.route('/train', endpoint='train')
class Train(Resource):
    @api.response(200, 'OK')
    def get(self):
        """
        Train Model endpoint
        """
        # Implement the train_model method asynchronously
        model.train_model()
        return 'OK', 200


@api.route('/predict', endpoint='predict')
class Predict(Resource):
    @api.response(200, 'OK')
    def post(self):
        """
        Predict endpoint
        """
        data = request.json
        return model.get_prediction(data), 200
