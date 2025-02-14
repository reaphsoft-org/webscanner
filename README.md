# webscanner
Webscanner tool for testing website credentials

### Find process in linux
```
sudo lsof -i :5432
```

### Start Celery Process
```
celery -A web_scanner  worker --loglevel=info
```

### Check Celery Configurations
```
celery -A web_scanner report | grep [BROKER]
```

### TODO
1. When a scan is ongoing, do not initiate another scan
2. Continue frooom step 5 of the Chat responses.

## References
1. [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities)