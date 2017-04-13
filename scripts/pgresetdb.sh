#!/bin/bash
echo "Completely wipe and reset database 'test'."
read -p "Are you sure? " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
    psql -c "CREATE USER test WITH PASSWORD 'zaphod';" -U postgres
    psql -c 'DROP DATABASE IF EXISTS test;' -U postgres
    psql -c 'CREATE DATABASE test OWNER test;' -U postgres
    psql < storage/sql/pgsql/storage.sql -U postgres test
    psql -c 'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO test;' -U postgres test
fi
echo
