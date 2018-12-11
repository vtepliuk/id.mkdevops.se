FROM python:2.7
WORKDIR /client
EXPOSE 5001
RUN pip install flask requests
COPY . .
ENTRYPOINT flask run -h 0.0.0.0 -p 5001
