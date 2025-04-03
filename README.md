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

### Bare Dependencies
```
beautifulsoup4==4.13.3
Django==4.2.6
ipinfo==5.1.1
python_whois==0.9.5
requests==2.32.3
spacy==3.8.4
xhtml2pdf==0.2.17
psycopg2==2.9.10
zaproxy==0.4.0
```

### Issues and Solutions
#### Docker showing ContainerConfig Error
Down the container and rebuild it.
```
docker-compose down
docker-compose up --build
```

#### Zap not connecting
Ensure that the ZAP_API_KEY is set, also ensure that the configuration allows connection from any host. See the attached docker-composer.yml for a sample and also see
this [link](https://www.zaproxy.org/docs/docker/about/#zap-headless)

### Running Docker Image
The docker image for this project is available at [link](https://hub.docker.com/repository/docker/osujir/webscanner)

To run the image, create a `docker-compose.yml` file with the contents below.
```
version: '3.9'

services:
  web:
    image: osujir/webscanner:latest
    # build: .
    ports:
      - "80:8000"
    depends_on:
      db:
        condition: service_healthy
      owasp_zap:
        condition: service_healthy
    env_file:
      - .env
    #volumes:
    #  - .:/app
    command: >
      sh -c "
      python manage.py makemigrations &&
      python manage.py migrate &&
      python manage.py runserver 0.0.0.0:8000
      "
  db:
    image: postgres:latest
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      - postgres_data:/var/lib/postgresql/data

  owasp_zap:
    image: zaproxy/zap-stable
    command: zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=${ZAP_API_KEY} -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config spider.maxChildren=30 -addoninstall technology-detection
    ports:
      - "8090:8090"
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8090"]
      interval: 10s
      timeout: 5s
      retries: 5
      
volumes:
  postgres_data:
```

Then create a `.env` file in the same directory as the `docker-compose.yml`

The `.env` file should have the following fields:
```
POSTGRES_USER="set_to_any_name"
POSTGRES_PASSWORD="set-to-any-character"
POSTGRES_DB="set_to_any_name"
DATABASE_HOST="db"

ZAP_API_KEY="set-to-any-set-of-characters"
IP_INFO_KEY="set-or-contact-repo-owners"
EMAIL_HOST_USER="set-to-your-mail-host-or-contact-repository-owners"
EMAIL_HOST_PASSWORD="set-to-your-mail-password-or-contact-repository-owners"
DJANGO_HOST="Set your cloud host ip here or use `localhost` if running locally"
NVD_API_KEY="Set-to-your-NVD-API-KEY-or-contact-repo-admins"
```

Then in the same directory, run
```
docker-compose up --build
```

And access the app in the specified host. 

## References
1. [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities)
2. [NVD Rate Limits](https://nvd.nist.gov/developers/start-here)
3. [Zap API Docs](https://www.zaproxy.org/docs/api/?python)
4. [Zap Proxy](https://pypi.org/project/zaproxy/)
5. [Zap Report CWE & WASC ID](https://groups.google.com/g/zaproxy-users/c/gD0d44bGeB8)
6. [CWE Def](https://cwe.mitre.org/)
7. [ZAP Alert Details](https://www.zaproxy.org/docs/alerts/)
8. [Sample CVE Data](https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2)
9. [NIST NVD CVE Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
10. [IPInfo](https://ipinfo.io/)
11. [IPInfo Git](https://github.com/ipinfo/python)
12. [ZAP Docker](https://www.zaproxy.org/docs/docker/)