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
1. Implement zap docker
2. Implement spacy docker

### Spacy
```
pip install spacy
python -m spacy download en_core_web_md 
```
`en_core_web_md` is about 34MB
`en_core_web_lg` is about 400MB

## References
1. [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities)
2. [NVD Rate Limits](https://nvd.nist.gov/developers/start-here)
3. [Zap API Docs](https://www.zaproxy.org/docs/api/?python)
4. [Zap Proxy](https://pypi.org/project/zaproxy/)
5. [Zap Report CWE & WASC ID](https://groups.google.com/g/zaproxy-users/c/gD0d44bGeB8)
6. [CWE Def](https://cwe.mitre.org/)