#!/bin/bash -x
#echo "Cloning VCDB ..."
#(git clone https://github.com/vz-risk/VCDB.git temp \
#&& mv temp/.git ../VCDB/.git) \
#|| echo "Database update failed, proceeding with stored VCDB"
#rm -rf temp
#echo "Proceeding to training..."
#./run_app/train_attribute.sh "LGBM RF KNN"
#./run_app/train_asset.sh "LGBM RF KNN"
#./run_app/train_action.sh "LGBM RF KNN"
./run_app/train_attribute.sh "LGBM"
./run_app/train_asset.sh "LGBM"
./run_app/train_action.sh "LGBM"
tail -F "KeepingContainerAlive"