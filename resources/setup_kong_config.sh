#!/bin/bash

KONG_ADMIN_URL=http://localhost:8001

SERVICE_NAME=httpbin
UPSTREAM_URL=https://eu.httpbin.org

ROUTE_NAME=httpbin-route
BASEPATH=/httpbin/v1

CONSUMER_NAME=test-user

# Delete the Consumer if it already exists
curl -X DELETE --url ${KONG_ADMIN_URL}/consumers/${CONSUMER_NAME}

# Delete all plugins for the Route
curl -X GET --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}/routes/${ROUTE_NAME}/plugins | jq -r '.data[] | .id' | xargs -I {} curl -i -X DELETE --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}/routes/${ROUTE_NAME}/plugins/{}

# Delete all plugins for the Service
curl -X GET --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}/plugins | jq -r '.data[] | .id' | xargs -I {} curl -i -X DELETE --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}/plugins/{}

# Delete the Route and Service if they already exist
curl -X DELETE --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}/routes/${ROUTE_NAME}
curl -X DELETE --url ${KONG_ADMIN_URL}/services/${SERVICE_NAME}

# Create a Gateway Service for the upstream service
curl -X POST --url ${KONG_ADMIN_URL}/services/ --data "name=${SERVICE_NAME}" --data "url=${UPSTREAM_URL}"

# Create a Route for the Gateway Service
curl -X POST --url ${KONG_ADMIN_URL}/services/httpbin/routes --data "paths[]=${BASEPATH}" --data "name=${ROUTE_NAME}"

# Create a Consumer
curl -X POST --url ${KONG_ADMIN_URL}/consumers/ --data "username=${CONSUMER_NAME}"

# Test the Gateway Service
curl -i -X GET --url http://localhost:8000${BASEPATH}/get
