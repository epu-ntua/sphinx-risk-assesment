#!/usr/bin/env bash
# flask db init
# flask db migrate
# flask db upgrade

#sshpass -p "tamarin-prover" ssh -4 -fN -o "StrictHostKeyChecking no" -L 0.0.0.0:3005:localhost:3001 tamarin-prover@tamarin
flask run --host=0.0.0.0 --no-reload

#cd docker

#./expect.sh tamarin-prover ssh -4 -fN -o "StrictHostKeyChecking no" -L 0.0.0.0:3005:localhost:3001 tamarin-prover@tamarin

