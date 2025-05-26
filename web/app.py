from flask import Flask
from routes.dashboard import dashboard
import logging

# Suppress only werkzeug request logs
class FilterOutRequests(logging.Filter):
    def filter(self, record):
        return not record.getMessage().startswith('127.0.0.1')

log = logging.getLogger('werkzeug')
log.addFilter(FilterOutRequests())

app = Flask(__name__)
app.register_blueprint(dashboard)

if __name__ == "__main__":
    app.run(debug=True)
