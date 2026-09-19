web: cd detector_service && gunicorn -k eventlet -w 1 --worker-connections 1000 --timeout 180 --keep-alive 60 --access-logfile - --error-logfile - -b 0.0.0.0:$PORT app:app
