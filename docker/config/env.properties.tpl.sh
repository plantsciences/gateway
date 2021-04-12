#!/bin/bash
cat << EOF
cluster.heartbeatInterval=1000
cluster.workerTimeout=5000
cluster.watchdogInterval=1000
cluster.memoryWarning.rss=1024
cluster.memoryWarning.heapTotal=300
cluster.memoryLimit.rss=2048
cluster.memoryLimit.heapUsed=500
cluster.workerRestartDelay=50
cluster.maxRestartBackoff=10
cluster.workerCount=1

frontend.logLevel=info
frontend.shutdownCode=pass123
frontend.port=$APP_PORT
frontend.ssl=false
frontend.private_key=
frontend.certificate=
frontend.cert_auth=
frontend.session_secret=YsDOJ6HtriYWK23OSeoEMSo687vc6yMIs9q9d4yzAUDer45tRTpsThFK0hIJWyFbNg6iXgmOvm2bhTgXVqFOMyqxQ6DB85NkQXyedOVlEvcUq98rAudPTDwjIPE17XiWPOF3cWUyWo1WJ6xPHT8ku2KsAlscyCFm3sWOZTIcgdQl9gzPvl8DrqAaIrnv1R8Bk7ztIsmAyFC3lGK82LFmxh1oSWBwxyMIzyvB2BWs8DLsvgiS4I7suStuDWoHKnMZJzQdxJAB5SItI0tTLFeQmbSVunoAo1t1dmk1FqjJ2JwPyXz0dfxteFMXGCODewXplAN3pYif2eCbNyJKjkhq1gS1FIhlQlupvRKmHeYEFg1QHuCiRO4pVngYiRNs0eQYMnDJCiskuWA3OeFKkF1ZZYqNwJWMt58gDcIFIiRkX4tDN4qON4mrWVmFfiBiEXaV0EFbtFwZvvfNYUwMygWzvTOMXVEiwZwfdH7BIuAiicOC3fmfKEYMZgknUMORsB2u

gateway.socketio.timeout=300
gateway.socketio.interval=120

gateway.redis.host=$REDIS_HOST
gateway.redis.port=6379
gateway.redis.password=$REDIS_PASS
gateway.redis.gatewaycontrolqueue=gateway
gateway.redis.max_attempts=1
gateway.redis.offline_queue=false

gateway.rabbitmq.host=$RABBIT_HOST
gateway.rabbitmq.port=5672
gateway.rabbitmq.login=$RABBIT_USER
gateway.rabbitmq.password=$RABBIT_PASS
gateway.rabbitmq.durable=true
gateway.rabbitmq.concurrency=5

EOF
