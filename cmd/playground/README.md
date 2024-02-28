# Playground

This is a place to use the available API

## Connecting to the dev database

To connect to dev, you'll need to run `make start_dev_cloud_sql_proxy`, and then run code that connects to the database.

Since all Go files in this folder aren't saved, here's a handy template for what the database connection string needs to look like:

```
dbString = `user=<user> password=<password> database=<database> host=127.0.0.1 port=5434 sslmode=disable`
```

Do not save real credentials to this file or anything that would end up in source control.
