# GCSSign

[Online documentation](https://hexdocs.pm/gcs_sign) | [Hex.pm](https://hex.pm/packages/gcs_sign)

<!-- MDOC !-->

`GCSSign` helps signing URLs and HTTP form requests for Google Cloud Storage.

This library provides logic for signing URLs and POST policies *locally* with JSON service account
key credentials.

## Examples

### Signing URLs

`GCSSign.sign_url_v4/2` can be used to sign URLs. Signed URLs give limited, temporary access to a
resource in a Google Cloud Storage bucket.

[Google's documentation](https://cloud.google.com/storage/docs/access-control/signed-urls) goes
into further detail on the usage and best practices of signed URLs.

```elixir
# Use a service account key
credentials = "GCP_CREDENTIALS" |> System.fetch_env!() |> Jason.decode!()

# Sign a simple URL
sign_opts = [bucket: "demo-bucket", key: "test.txt"]
url = GCSSign.sign_url_v4(credentials, sign_opts)

# Sign a URL with custom expiration time
sign_opts = [bucket: "demo-bucket", key: "test.txt", expires_in: 60]
url = GCSSign.sign_url_v4(credentials, sign_opts)

# Sign a URL with custom headers
headers = [
  # Or use https://hex.pm/packages/content_disposition
  # {"response-content-disposition", ContentDisposition.format(disposition: :attachment, filename: "file.txt")},
  {"response-content-disposition", "inline; filename=\"file.txt\"; filename*=UTF-8''file.txt"},
  {"response-content-type", "text/plain"}
]
sign_opts = [bucket: "demo-bucket", key: "test.txt", expires_in: 60]
url = GCSSign.sign_url_v4(credentials, sign_opts)
```

### Signing XML POST Policies

Signed POST policies can be used to allow external parties limited upload access to a bucket. A
[policy document](https://cloud.google.com/storage/docs/authentication/signatures#policy-document)
can be used to limit in which bucket, with what key a file can be uploaded, and it supports
setting file-size limits.

`GCSSign.sign_post_policy_v4/2` can be used to sign a POST policy. It requires a bucket and key
and returns a map with a URL and a map of fields that should be passed as parameters in the
upload request.

[Google's documentation](https://cloud.google.com/storage/docs/xml-api/post-object-forms#usage_and_examples)
describes how this can be used to perform a multipart upload.

```elixir
# Use a service account key
credentials = "GCP_CREDENTIALS" |> System.fetch_env!() |> Jason.decode!()

# Sign a simple URL
sign_opts = [
  expires_in: 600,
  bucket: "demo-bucket",
  key: "test.txt",
  fields: %{
    "content-type" => "text/plain",
    "cache-control" => "public, max-age=31536000"
  },
  conditions: [["content-length-range", 0, 2_000_000]]
]

{:ok, policy} = GCSSign.sign_post_policy_v4(credentials, sign_opts)
```

<a id="authorizer-options" />

## Authorizer options
Google Cloud Storage accepts two different options for passing the credential scope's authorizer:

- `client_id`: The ID of the service account key
- `client_email`: The service account email

GCSSign will use the `client_id` by default because it exposes the least information when used in
XML POST with HTML forms. You can optionally set `authorizer: :client_email` in `sign_opts` to
make the credential scope use `client_email`.

[Read more about authorizer in Google's documentation](https://cloud.google.com/storage/docs/authentication/canonical-requests#required-query-parameters)

<!-- MDOC !-->

## Installation

Add `gcs_sign` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:gcs_sign, "~> 1.0.0"}]
end
```

## License

This library is MIT licensed. See the
[LICENSE](https://raw.github.com/jeroenvisser101/gcs_sign/main/LICENSE)
file in this repository for details.
