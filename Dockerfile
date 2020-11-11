FROM python:3.8-slim

COPY . .

WORKDIR .

RUN pip install -r requirements.txt

EXPOSE 5002

ENTRYPOINT ["flask"]

CMD ["run", "--host=0.0.0.0"]

