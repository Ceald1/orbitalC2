#!/bin/bash

docker compose up -d

swag init

go run .
