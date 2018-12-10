import os
import pymongo
import pandas as pd
import ipaddress as ip
import tldextract
import pickle
import re
import numpy as np
import logging

from urlparse import urlparse
from settings import config_by_name
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier


class MaliciousUrlModel:
    settings = config_by_name[os.getenv('sysenv', 'prod')]()
    db_url = 'mongodb://{}:{}@{}/{}'.format(settings.DB_USER,
                                            os.getenv('DB_PASS'),
                                            settings.DB_HOST,
                                            settings.DB)

    POPULAR_TARGETS = {'paypal', 'facebook', 'google', 'microsoft', 'outlook', 'chase', 'apple',
                       'banco', 'amazon', 'dropbox', 'yahoo', 'linkedin', 'netflix', 'gmail', 'boa',
                       'wellsfargo', 'dhl', 'fedex', 'comcast', 'xfinity', 'att', 'bbva', 'orange',
                       'santander', 'rbc', 'rbaccess'}

    POPULAR_ABUSED_TLDS = {'gq', 'cf', 'tk', 'ga', 'ml', 'loan', 'men', 'click', 'date', 'biz',
                           'country', 'kim', 'science', 'work', 'ninja', 'xyz', 'faith', 'zip',
                           'racing', 'cricket', 'win', 'space', 'accountant', 'realtor', 'top',
                           'stream', 'christmas', 'gdn', 'mom', 'pro', 'info', 'online', 'club',
                           'website'}

    POPULAR_ABUSED_FILE_EXT = {'.zip', '.exe', '.bin', '.jar', '.dll', '.pl'}
    POPULAR_ABUSED_DELIMITERS = {';', '_', '?', '=', '&', '%', '.', '#'}
    HASH_PATTERN = r'[0-9a-f]+'

    LABELS = {0: 'BENIGN', 1: 'MALICIOUS'}
    FILENAME = 'malicious_classifier.sav'

    DF_STRUCTURE = pd.DataFrame(columns=['url', 'length', 'popular_target', 'subdomain_count', 'popular_abuse_tld',
                                         'sub_directory_count', 'popular_ext', 'popular_delimiter', 'args_exist',
                                         'is_ip_address', 'hash_present', 'com_dash_present', 'label'])

    def __init__(self):
        self._model = DecisionTreeClassifier(random_state=0, max_depth=8)
        self._logger = logging.getLogger(__name__)

    @classmethod
    def _count_sub_domains(cls, subdomain):
        if not subdomain:
            return 0
        return len(subdomain.split('.'))

    @classmethod
    def _count_sub_directories(cls, path):
        count = 0
        if not path:
            return count
        path_parts = path.lower().split('/')
        for part in path_parts:
            if not (part == '' or '.' in part):
                count += 1
        return count

    @classmethod
    def _is_arg_exists(cls, url_parse_output):
        if url_parse_output.params or url_parse_output.query or url_parse_output.fragment:
            return 1
        return 0

    @classmethod
    def _is_com_dash_present(cls, domain):
        if domain and domain.startswith('com-'):
            return 1
        return 0

    @classmethod
    def _is_ip_address(cls, domain):
        try:
            if ip.ip_address(unicode(domain)):
                return 1
        except ValueError:
            return 0
        return 0

    def _count_popular_abused_delim(self, url):
        count = 0
        for each in url:
            if each in self.POPULAR_ABUSED_DELIMITERS:
                count += 1
        return count

    def _is_popular_target_present(self, path, subdomain):
        for target in self.POPULAR_TARGETS:
            if target in path or target in subdomain:
                return 1
        return 0

    def _is_popular_abuse_tld_present(self, extension):
        if extension in self.POPULAR_ABUSED_TLDS:
            return 1
        return 0

    def _is_popular_abuse_ext_present(self, url):
        filename, file_extension = os.path.splitext(url)
        if file_extension in self.POPULAR_ABUSED_FILE_EXT:
            return 1
        return 0

    def _is_hash_present(self, path):
        if not path:
            return 0
        path_parts = path.lower().split('/')
        for part in path_parts:
            length = len(part)
            if (length == 16 or length == 32 or length == 64) and re.match(self.HASH_PATTERN, part):
                return 1
        return 0

    def load_model(self):
        saved_model = None
        try:

            saved_model = pickle.load(open('service/utils/saved-models/' + self.FILENAME, 'rb'))
        except IOError:
            self._logger.error('Unable to load the saved model from file : {}'.format(self.FILENAME))
        return saved_model

    def _fetch_and_prepare_data(self):
        with pymongo.MongoClient(self.db_url) as client:
            collection = client.get_database()['incidents']
            phishing_url_df = pd.DataFrame(list(collection.find({'$and': [
                {'$or':
                    [
                        {'close_reason': 'suspended'},
                        {'close_reason': 'intentionally_malicious'}
                    ]}, {'type': 'PHISHING'}]}, {'source': 1, '_id': 0})))
            malware_url_df = pd.DataFrame(list(collection.find({'$and': [
                {'$or':
                    [
                        {'close_reason': 'suspended'},
                        {'close_reason': 'intentionally_malicious'}
                    ]}, {'type': 'MALWARE'}]}, {'source': 1, '_id': 0})))

        external_df = pd.read_csv('service/utils/data/dataset.csv')
        benign_url_df = external_df[external_df['Label'] == 0]

        phishing_url_df = phishing_url_df.rename(index=str, columns={"source": "url"})
        malware_url_df = malware_url_df.rename(index=str, columns={"source": "url"})
        benign_url_df = benign_url_df.rename(index=str, columns={"URL": "url", "Label": "label"})
        phishing_url_df['label'] = 1
        malware_url_df['label'] = 1

        frames = [phishing_url_df, malware_url_df, benign_url_df]
        final_url_df = pd.concat(frames)
        final_url_df = final_url_df.reset_index(drop=True)
        return final_url_df

    def _get_features(self, url, label=None):
        tld_output = tldextract.extract(url)
        url_parse_output = urlparse(url)

        features = list()
        features.append(url)
        features.append(len(url))
        features.append(self._is_popular_target_present(url_parse_output.path, tld_output.subdomain))
        features.append(self._count_sub_domains(tld_output.subdomain))
        features.append(self._is_popular_abuse_tld_present(tld_output.suffix))
        features.append(self._count_sub_directories(url_parse_output.path))
        features.append(self._is_popular_abuse_ext_present(url))
        features.append(self._count_popular_abused_delim(url_parse_output.path))
        features.append(self._is_arg_exists(url_parse_output))
        features.append(self._is_ip_address(tld_output.domain))
        features.append(self._is_hash_present(url_parse_output.path))
        features.append(self._is_com_dash_present(tld_output.domain))
        features.append(label)
        return features

    def _build_feature_df(self):
        feature_df = self.DF_STRUCTURE
        final_url_df = self._fetch_and_prepare_data()
        for i in range(len(final_url_df)):
            features = self._get_features(final_url_df['url'].loc[i], final_url_df['label'].loc[i])
            feature_df.loc[i] = features
        feature_df = feature_df.infer_objects()
        return feature_df

    def train_model(self):
        """
         Keep training the model at fixed intervals (Either batch or adhoc, whichever is more efficient)
         Build an endpoint (seymour) for external trusted contributors to submit a url with a label to
          then be added to a collection in mongo for retraining.
         API needs to be fed fully qualified urls. Some sort of validation needs to be performed.
        :return:
        """
        self._logger.info('Initiating model training')
        feature_df = self._build_feature_df()
        x = feature_df.drop(['url', 'label'], axis=1).values
        y = feature_df['label'].values
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=1)
        self._model.fit(x_train, y_train)
        pickle.dump(self._model, open('service/utils/saved-models/' + self.FILENAME, 'wb'))
        self._logger.info('Model accuracy: {} '.format(self._model.score(x_test, y_test)))
        self._logger.info('Model trained successfully')

    def get_pickle(self):
        """
        This method would return the latest saved model so that projects accessing this endpoint won't have
        to make subsequent request till the model is retrained.
        :return:
        """
        pass

    def get_url_features(self):
        """
        This method would return the features that are used for making predictions for a particular url.
        For internal DCU team members only.
        :return:
        """
        pass

    def get_prediction(self, data):
        result = self.DF_STRUCTURE
        error_message = 'Unable to predict at this time'
        if not (data and data['url']):
            return error_message
        url = data['url']
        results = self._get_features(url=url)
        result.loc[0] = results
        result = result.drop(['url', 'label'], axis=1).values
        model = self.load_model()
        if not model:
            self._logger.info('Unable to load saved model.')
            return error_message
        predicted_label = model.predict(result)
        if not isinstance(predicted_label, np.ndarray):
            return None
        return self.LABELS[predicted_label[0]]















