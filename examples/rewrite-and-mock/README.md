# Rewrite and Mock Example

This example demonstrates how to use go-mitmproxy to:
1. Rewrite request host and path
2. Return mock responses from local files for specific requests

## Features

- **Request Rewriting**: Modify host and path of incoming requests
- **Mock Responses**: Return predefined responses from local files based on request method, host, and path
- **Flexible Configuration**: Easy to customize rewrite rules and mock file location

## Usage

### 1. Start the Proxy

Run the example:

```bash
go run main.go
```

The proxy will start on `http://localhost:9080` and use a mock directory at `/tmp/go-mitmproxy-mock` by default.

### 2. Configure Your Browser/Application

Set your browser or application to use `http://localhost:9080` as the HTTP proxy.

### 3. Create Mock Files

Mock files should be placed in the mock directory with the following structure:

```
{mock_dir}/
└── {safe_host}/
    └── {method}_{safe_path}.json
```

Where:
- `{safe_host}` is the host with dots replaced by underscores (e.g., `example.com` becomes `example_com`)
- `{method}` is the HTTP method (GET, POST, etc.)
- `{safe_path}` is the path with slashes replaced by underscores (e.g., `/api/v1/users` becomes `api_v1_users`)

### Example Mock File

Create a mock file for `GET http://example.com/hello`:

```bash
mkdir -p /tmp/go-mitmproxy-mock/example_com
echo '{"message": "Hello from mock!"}' > /tmp/go-mitmproxy-mock/example_com/GET_hello.json
```

When you make a request to `http://example.com/hello` through the proxy, you will receive the mock response.

## Rewrite Rules

The current example includes the following rewrite rules:

1. **Host Rewrite**: Changes `example.com` to `www.example.org`
2. **Path Rewrite**: Changes `/api/v1/` to `/api/v2/`

You can customize these rules by modifying the `Requestheaders` method in `main.go`.

## Customization

### Change Mock Directory

To use a custom mock directory, modify the `NewRewriteAndMock` call in `main.go`:

```go
p.AddAddon(NewRewriteAndMock("./my-mock-dir"))
```

### Add More Rewrite Rules

Edit the `Requestheaders` method to add more rewrite rules:

```go
func (a *RewriteAndMock) Requestheaders(f *proxy.Flow) {
    // Add your custom rewrite rules here
    if f.Request.URL.Host == "example.net" {
        f.Request.URL.Host = "example.org"
    }
    // ...
}
```

### Change Mock File Format

Modify the `getMockFile` method to change the mock file naming convention and the `createMockResponse` method to handle different content types.
