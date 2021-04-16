FROM python:3.8-slim

COPY . .

WORKDIR .

#COPY requirements.txt .
RUN pip install -r requirements.txt
#RUN flask db init
#RUN flask db migrate
#RUN flask db upgrade
#RUN python3 from app import db
#RUN python3 db.create_all()

EXPOSE 5002

ENTRYPOINT ["flask"]

CMD ["run", "--host=0.0.0.0"]

