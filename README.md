## Usage

### server

```bash
cargo run --bin websocket-server
# Started http server: 127.0.0.1:8080
```

### web page

- [http://localhost:8080/secret](http://localhost:8080/secret)
- [http://localhost:8080/whitelist](http://localhost:8080/whitelist)

### client

```bash
cargo run --bin websocket-client
```

To change secret number, manually change it in `src/client.rs` and `line 27`