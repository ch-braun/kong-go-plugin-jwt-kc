#!/bin/bash

CLIENT_ID=test-user
CLIENT_SECRET=changeme

TOKEN_ENDPOINT=http://kc:8080/realms/default/protocol/openid-connect/token
GATEWAY_URL=http://localhost:8000/httpbin/v1/get

ACCESS_TOKEN_RESPONSE=$(curl -vk -X POST -u ${CLIENT_ID}:${CLIENT_SECRET} -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" ${TOKEN_ENDPOINT})

ACCESS_TOKEN=$(echo ${ACCESS_TOKEN_RESPONSE} | jq -r '.access_token')

curl -vk -X GET -H "Authorization: Bearer ${ACCESS_TOKEN}" ${GATEWAY_URL}