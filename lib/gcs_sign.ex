defmodule GCSSign do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)

  @algo "GOOG4-RSA-SHA256"
  @default_expiration 60 * 60
  @google_cloud_storage_host "storage.googleapis.com"

  @typedoc """
  A HTTP method.

  Accepts atoms and case-insensitive strings. Every method will be uppercased and converted to a
  string before being encoded.
  """
  @type http_verb() :: atom() | String.t()

  @typedoc """
  A list of headers.

  Headers are case-insensitive. The same header key can appear multiple times and will be handled
  accordingly according to the
  [documenation](https://cloud.google.com/storage/docs/authentication/canonical-requests#about-headers).
  """
  @type headers() :: [{String.t(), String.t()}]

  @typedoc """
  A query string in the form of a list of tuples.

  Optionally accepts atoms as keys that will be transformed to strings. Only strings are allowed
  as values.
  """
  @type query() :: [{String.t() | atom(), String.t()}]

  @typedoc """
  A condition for a POST policy.

  See [Google's documentation](https://cloud.google.com/storage/docs/authentication/signatures#policy-document)
  for more.

  ## Examples

  ```elixir
  # Exact matching
  ["eq", "$x-custom-header", "value"]
  %{"x-goog-meta-tenant" => "tenant-1"}

  # Starts with
  ["starts-with", "$key", "some/prefix/key"]
  ["starts-with", "$key", ""] # no restrictions on value

  # Content-Length range
  ["content-length-range", 0, 20_000_000]
  """
  @type condition() :: %{required(String.t()) => String.t()} | [String.t() | integer()]

  @typedoc "A list of conditions."
  @type conditions() :: [condition()]

  @typedoc """
  The parsed JSON service account key.

  Contains the `private_key` and `client_id`/`client_email`.
  """
  @type credentials() :: %{required(String.t()) => term()}

  @typedoc """
  Additional fields for a signed POST policy.

  [Supported fields](https://cloud.google.com/storage/docs/xml-api/post-object-forms#form_fields)
  """
  @type fields() :: %{required(String.t()) => term()}

  @typedoc """
  An authorizer key type.

  Defaults to `:client_id`, but can optionally be set to `:client_email` to use the
  service account's email as authorizer. See "Authorizer" in the module documentation for more.
  """
  @type authorizer() :: :client_id | :client_email

  @typedoc "A signed POST policy"
  @type signed_policy() :: %{url: String.t(), fields: fields()}

  @typedoc "Shared options for both URL and POST policy signing"
  @type common_option() ::
          {:authorizer, authorizer()}
          | {:expires_in, non_neg_integer()}
          | {:bucket, String.t()}
          | {:path, String.t()}
          | {:key, String.t()}
          | {:utc_now, Calendar.datetime()}

  @typedoc "Options specific for URL signing"
  @type url_option() ::
          {:payload, String.t() | nil}
          | {:method, http_verb()}
          | {:host, String.t()}
          | {:query, query()}
          | {:headers, headers()}

  @typedoc "Options specific for POST policy signing"
  @type post_policy_option() :: {:conditions, [condition()]} | {:fields, fields()}

  @doc """
  Signs a POST policy

  Signed POST policies can be used to allow external parties limited upload access to a bucket. A
  [policy document](https://cloud.google.com/storage/docs/authentication/signatures#policy-document)
  can be used to limit in which bucket, with what key a file can be uploaded, and it supports
  setting file-size limits.

  [Google's documentation](https://cloud.google.com/storage/docs/xml-api/post-object-forms#usage_and_examples)
  describes how this can be used to perform a multipart upload.

  ## Options

    * `:bucket` (`t:String.t/0`) - The name of the GCS bucket.
    * `:key` (`t:String.t/0`) - The key to the file in the bucket, without leading slash.
    * `:authorizer`  (`t:authorizer/0`) - The type of authorizer to use, see
       "[Authorizer](#authorizer-options)" in the module documentation. Defaults to `:client_id`
    * `:expires_in` (`t:integer/0`) - Time in seconds that the POST policy should stay valid for.
       Defaults to `3600` (1 hour). Cannot exceed 7 days or 604800 seconds.
    * `:conditions` (`t:conditions/0`) - Additional conditions to impose on the policy, see
       "Conditions" below.
    * `:fields` (`t:fields/0`) - Additional fields to include in the signed policy, see "Fields"
       below.
    * `:utc_now` (`t:Calendar.datetime/0`) - Optionally uses a different time instead of
      `DateTime.utc_now/0`.

  ## Conditions

  Conditions can be in either 3-element list format, or as a map:

  ```elixir
  conditions = [
    ["eq", "$x-custom-header", "value"],
    ["content-length-range", 0, 20_000_000],
    %{"x-goog-meta-tenant" => "tenant-1"}
  ]
  ```

  To learn more about the supported conditions, see
  [Google's documentation](https://cloud.google.com/storage/docs/authentication/signatures#policy-document).

  ## Fields

  Additional fields [supported by GCS](https://cloud.google.com/storage/docs/xml-api/post-object-forms#form_fields)
  can be passed as `:fields` and will be signed accordingly.

  ```elixir
  fields = %{
    "cache-control" => "public, max-age=31536000"
    "content-type" => "text/plain",
  }
  ```
  """
  @spec sign_post_policy_v4(credentials(), [common_option() | post_policy_option()]) ::
          {:ok, signed_policy()}
  def sign_post_policy_v4(credentials, sign_opts) do
    # Even though bucket isn't required in these requests, leaving this open may lead to unexpected
    # security issues, and so it is a required option here, which also makes it easier to specify
    # the bucket name in the url, which is required
    bucket = Keyword.fetch!(sign_opts, :bucket)
    key = Keyword.fetch!(sign_opts, :key)
    authorizer = Keyword.get(sign_opts, :authorizer, :client_id)
    expires_in = Keyword.get(sign_opts, :expires_in, @default_expiration)
    conditions = Keyword.get(sign_opts, :conditions, [])
    fields = Keyword.get(sign_opts, :fields, %{})

    if expires_in > 604_800 do
      raise ArgumentError, "expires_in cannot exceed 7 days (604800 seconds)"
    end

    utc_now = Keyword.get_lazy(sign_opts, :utc_now, &DateTime.utc_now/0)
    iso_date = DateTime.to_date(utc_now) |> Date.to_iso8601(:basic)
    iso_timestamp = utc_now |> DateTime.truncate(:second) |> DateTime.to_iso8601(:basic)
    expires_at = utc_now |> DateTime.add(expires_in)

    credential_scope = credential_scope(iso_date)
    {rsa_key, authorizer} = get_credentials(credentials, authorizer)
    credential = "#{authorizer}/#{credential_scope}"

    fields =
      Map.merge(fields, %{
        "bucket" => bucket,
        "key" => key,
        "x-goog-algorithm" => @algo,
        "x-goog-credential" => credential,
        "x-goog-date" => iso_timestamp
      })

    fields_conditions = fields_to_conditions(fields)

    policy = policy(iso_timestamp, credential, expires_at, conditions ++ fields_conditions)
    signature = do_sign_rsa_sha256_hex(rsa_key, policy)
    fields = fields |> Map.put("policy", policy) |> Map.put("x-goog-signature", signature)

    signed_policy = %{
      url: Enum.join(["https://" <> @google_cloud_storage_host, bucket], "/"),
      fields: fields
    }

    {:ok, signed_policy}
  end

  @doc """
  Signs a URL with V4 signing process

  Signed URLs give limited permission and time to make an authorized request for anyone in
  possession of the URL without requiring the requester to have a Google account with access to
  the resource. Signed URLs contain authentication information in the query string to authenticate
  a request on behalf of the service account used to sign the URL.

  To learn more about signed URLs, see
  [Google's documentation](https://cloud.google.com/storage/docs/access-control/signed-urls).

  ## Options

    * `:bucket` (`t:String.t/0`) - The name of the GCS bucket.
    * `:key` (`t:String.t/0`) - The key to the file in the bucket, without leading slash.
    * `:authorizer`  (`t:authorizer/0`) - The type of authorizer to use, see
       "[Authorizer](#authorizer-options)" in the module documentation. Defaults to `:client_id`
    * `:expires_in` (`t:integer/0`) - Time in seconds that the POST policy should stay valid for.
       Defaults to `3600` (1 hour). Cannot exceed 7 days or 604800 seconds.
    * `:method` (`t:http_verb/0`) - The key to the file in the bucket, without leading slash.
       Default: `"GET"`
    * `:headers` (`t:headers/0`) - Headers that should be included in the request. Defaults to the
       host header.
    * `:payload` (`t:String.t/0` or `nil`) - The request body required when making the request.
       Defaults to `nil`. `nil` is converted to `UNSIGNED-PAYLOAD`, meaning the payload isn't
       signed.
    * `:query` (`t:query/0`) - The query parameters required in the request.
    * `:host` (`t:String.t/0`) - The cloud storage hostname to use. Defaults to
      `#{inspect(@google_cloud_storage_host)}`. When set to a custom hostname, the path will not
      contain the bucket name to allow for
      [Custom CNAME](https://cloud.google.com/storage/docs/domain-name-verification)
      or
      [Backend buckets](https://cloud.google.com/load-balancing/docs/https/ext-load-balancer-backend-buckets)
      in a loadbalancer setup.
    * `:utc_now` (`t:Calendar.datetime/0`) - Optionally uses a different time instead of
      `DateTime.utc_now/0`.
  """
  @spec sign_url_v4(credentials(), [common_option() | url_option()]) :: String.t()
  def sign_url_v4(credentials, sign_opts) do
    bucket = Keyword.fetch!(sign_opts, :bucket)
    key = Keyword.fetch!(sign_opts, :key)
    authorizer = Keyword.get(sign_opts, :authorizer, :client_id)
    method = Keyword.get(sign_opts, :method, "GET")
    expires_in = Keyword.get(sign_opts, :expires_in, @default_expiration)
    headers = Keyword.get(sign_opts, :headers, [])
    payload = Keyword.get(sign_opts, :payload)
    query = Keyword.get(sign_opts, :query, [])
    host = Keyword.get(sign_opts, :host, @google_cloud_storage_host)
    utc_now = Keyword.get_lazy(sign_opts, :utc_now, &DateTime.utc_now/0)

    if expires_in > 604_800 do
      raise ArgumentError, "expires_in cannot exceed 7 days (604800 seconds)"
    end

    path =
      case host do
        @google_cloud_storage_host -> Enum.join(["", bucket, key], "/")
        _cname_host -> "/#{key}"
      end

    iso_date = DateTime.to_date(utc_now) |> Date.to_iso8601(:basic)
    iso_timestamp = utc_now |> DateTime.truncate(:second) |> DateTime.to_iso8601(:basic)

    {rsa_key, authorizer} = get_credentials(credentials, authorizer)
    credential_scope = credential_scope(iso_date)
    credential = "#{authorizer}/#{credential_scope}"

    {headers, signed_headers} =
      headers
      |> Enum.map(fn {key, value} -> {String.downcase(key), value} end)
      |> Enum.sort_by(&elem(&1, 1))
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Map.put_new("host", [host])
      |> Enum.reduce({[], []}, fn {key, values}, {headers, signed_headers} ->
        # first header shouldn't have a leading separator
        {headers_sep, signed_sep} = if headers == [], do: {[], []}, else: {?\n, ?;}
        values = Enum.intersperse(values, ?,)

        {[headers, headers_sep, key, ?: | values], [signed_headers, signed_sep, key]}
      end)
      |> case do
        {headers, signed_headers} ->
          {IO.iodata_to_binary(headers), IO.iodata_to_binary(signed_headers)}
      end

    query = [
      {"x-goog-algorithm", @algo},
      {"x-goog-credential", credential},
      {"x-goog-date", iso_timestamp},
      {"x-goog-expires", to_string(expires_in)},
      {"x-goog-signedheaders", signed_headers} | query
    ]

    canonical_request = canonical_request(method, path, query, headers, signed_headers, payload)

    hashed_canonical_request =
      :sha256 |> :crypto.hash(canonical_request) |> Base.encode16(case: :lower)

    string_to_sign =
      Enum.join([@algo, iso_timestamp, credential_scope, hashed_canonical_request], "\n")

    signature = do_sign_rsa_sha256_hex(rsa_key, string_to_sign)
    query = [{"x-goog-signature", signature} | query]

    URI.to_string(%URI{
      scheme: "https",
      host: host,
      path: path,
      query: URI.encode_query(query, :rfc3986)
    })
  end

  @spec do_sign_rsa_sha256_hex(:public_key.private_key(), String.t()) :: String.t()
  defp do_sign_rsa_sha256_hex(rsa_key, string_to_sign) do
    string_to_sign
    |> :public_key.sign(:sha256, rsa_key)
    |> Base.encode16(case: :lower)
  end

  @spec fields_to_conditions(Enumerable.t()) :: [condition()]
  defp fields_to_conditions(fields) do
    Enum.flat_map(fields, fn
      # The signature and policy should be skipped, they are either derived from or depenencies of
      # the conditions to be generated
      {key, _value} when key in ["x-goog-signature", "policy"] -> []
      {key, value} -> [["eq", "$#{key}", value]]
    end)
  end

  @spec canonical_request(
          http_verb(),
          String.t(),
          query(),
          String.t(),
          String.t(),
          String.t() | nil
        ) :: String.t()
  defp canonical_request(http_verb, path, query, headers, signed_headers, payload) do
    canonical_query_string =
      query
      |> Enum.sort_by(&elem(&1, 0), :asc)
      |> URI.encode_query(:rfc3986)

    [
      String.upcase(to_string(http_verb)),
      path,
      canonical_query_string,
      headers,
      "",
      signed_headers,
      payload || "UNSIGNED-PAYLOAD"
    ]
    |> Enum.join("\n")
  end

  @spec policy(String.t(), String.t(), DateTime.t(), [condition()]) :: String.t()
  defp policy(iso_timestamp, credential, expires_at, conditions) do
    expiration = expires_at |> DateTime.truncate(:second) |> DateTime.to_iso8601()

    conditions = [
      %{"x-goog-algorithm" => @algo},
      %{"x-goog-credential" => credential},
      %{"x-goog-date" => iso_timestamp}
      | conditions
    ]

    %{"expiration" => expiration, "conditions" => conditions}
    |> Jason.encode!()
    |> Base.encode64()
  end

  @spec get_credentials(credentials(), authorizer()) :: {:public_key.private_key(), String.t()}
  defp get_credentials(%{"private_key" => pem_bin, "client_id" => authorizer}, :client_id) do
    [pem_key_data] = :public_key.pem_decode(pem_bin)
    rsa_key = :public_key.pem_entry_decode(pem_key_data)

    {rsa_key, authorizer}
  end

  defp get_credentials(%{"private_key" => pem_bin, "client_email" => authorizer}, :client_email) do
    [pem_key_data] = :public_key.pem_decode(pem_bin)
    rsa_key = :public_key.pem_entry_decode(pem_key_data)

    {rsa_key, authorizer}
  end

  defp get_credentials(invalid_credentials, _authorizer) do
    raise """
    invalid credentials passed, gcs_sign requires `private_key` and `client_id` or `client_email` \
    to be present, got: #{inspect(Map.keys(invalid_credentials))}
    """
  end

  @spec credential_scope(String.t()) :: String.t()
  defp credential_scope(iso_date), do: "#{iso_date}/auto/storage/goog4_request"
end
