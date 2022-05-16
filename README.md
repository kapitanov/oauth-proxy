# oauth-proxy

A proxy server with OAuth2 authentication (via Github).

## How to run

Use docker compose:

```yaml
version: '2.4'
services:
    oauth-proxy:
        build: .
        restart: always
        ports:
            - 80:80
        environment:
            GH_CLIENT_ID: my-client-id
            GH_CLIENT_SECRET: my-client-secret
            GH_USERS: my-user-1, my-user-2, my-user-3
            BACKEND_URL: http://my-backend:80
            PUBLIC_URL: http://my-server.com
```

## Parameters

| Env variable       | Default value | Description                          |
| ------------------ | ------------- | ------------------------------------ |
| `GH_CLIENT_ID`     |               | Github client ID                     |
| `GH_CLIENT_SECRET` |               | Github client secret                 |
| `GH_USERS`         |               | Comma-separated list of Github users |
| `BACKEND_URL`      |               | Backend URL                          |
| `LISTEN_ADDR`      | `0.0.0.0:80`  | HTTP endpoint to listen              |
| `PUBLIC_URL`       |               | Public URL                           |

## License

[MIT](LICENSE)
