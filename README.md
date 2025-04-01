# User Authentication API
[![CI Build](https://github.com/eyadarouaz/auth-api/actions/workflows/ci-build.yaml/badge.svg)](https://github.com/eyadarouaz/auth-api/actions/workflows/ci-build.yaml)  
API for authentication microservice  
## Commands

### Setting Up the Environment
To set up the environment, run the following command:
```sh
bash ./bin/setup.sh
```
To activate the virtual environment, run: 
```sh
source venv/bin/activate
```
### Linting
To check the code for style guide enforcement and linting errors, use:
```sh
flake8
```
To format code, run:
```sh
black .
```
To sort imports, run:
```sh
isort .
```

### Testing
To run the tests, use:
```sh
pytest -v --cov=app --cov-report=term-missing
```

### Starting the App
To start the application, execute:
```sh
uvicorn app.main:app --reload
```
