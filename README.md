# fireblocks-passthrough-go

## Intro
A Golang passthrough for the [Fireblocks API](https://developers.fireblocks.com/reference/api-overview)

The reason i make this library is to make it easy to call the Fireblocks API and separate the logic for processing the response. The response is returned as `interface{}`

## Example

### Initialization
```go
apiKey := "FIREBLOCKS_API_KEY"
privateKey, err := ReadPrivateKey("PATH_TO_PRIVATE_KEY")
if err != nil {
  panic("Failed to read private key")
}
fireblocksUrl := "https://api.fireblocks.io"
timeout := 0
sdk := NewInstance(privateKey, apiKey, fireblocksUrl, timeout)
```

### GET Method
```go
payload := make(map[string]interface{})
marshalled, err := json.Marshal(payload)
method := "GET"
path := "/v1/supported_assets"
result, err := sdk.Passthrough(method, path, marshalled)
```

### POST Method
```go
payload := make(map[string]interface{})
marshalled, err := json.Marshal(payload)
method := "POST"
path := "/v1/webhooks/resend"
result, err := sdk.Passthrough(method, path, marshalled)
```

## To-Do
- Example for PUT & DELETE methods
- Improve performance


#### Notes
Inspired by [caxqueiroz/fireblocks-sdk](https://github.com/caxqueiroz/fireblocks-sdk)