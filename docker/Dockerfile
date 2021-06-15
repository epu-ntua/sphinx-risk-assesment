FROM python:3.8-slim

COPY . .

WORKDIR .

#COPY requirements.txt .
RUN apt-get update
RUN apt-get -y install ssh
RUN apt-get install libgomp1
RUN apt-get -y install sshpass
RUN pip install -r requirements.txt
#RUN flask db init
#RUN flask db migrate
#RUN flask db upgrade

#RUN chmod 755 ./docker/expect.sh
#RUN flask db init
#RUN flask db migrate
#RUN flask db upgrade
#RUN python3 from app import db
#RUN python3 db.create_all()

EXPOSE 5002

#CMD ["./expect.sh tamarin-prover ssh -o "StrictHostKeyChecking no" -L localhost:3005:localhost:3001 tamarin-prover@<tamarin-container-ip>"]

#ENTRYPOINT ["flask"]



#CMD ["bash", "run"]


