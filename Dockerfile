FROM --platform=linux/x86-64 python:3.9-slim

WORKDIR /build

COPY app /build/app

RUN pip install -r app/requirements.txt

EXPOSE 5000

CMD [ "python", "-u", "app/main.py" ]