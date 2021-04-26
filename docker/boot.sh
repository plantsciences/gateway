#!/bin/bash

# Set ENV Vars
./docker/config/env.properties.tpl.sh > ./docker/config/env.properties
cat ./docker/config/env.properties

echo "RUN_MODE: $RUN_MODE"
if [[ $RUN_MODE = "DEV" ]]
then
  npm run start:dev -- s ./docker/config/env.properties
else
  npm start s ./docker/config/env.properties
fi
