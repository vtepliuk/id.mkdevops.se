FROM python:3.6
WORKDIR /client
EXPOSE 5001
RUN pip install flask requests PyJWT
COPY . .
ENTRYPOINT flask run -h 0.0.0.0 -p 5001
