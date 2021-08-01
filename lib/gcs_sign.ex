defmodule GCSSign do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)

  @algo "GOOG4-RSA-SHA256"
  @default_expiration 60 * 60
  @google_cloud_storage_host "storage.googleapis.com"

  @type http_verb() :: atom() | String.t()
  @type headers() :: [{String.t(), String.t()}]
  @type query() :: [{String.t() | atom(), String.t()}]
  @type condition() :: term()
  @type credentials() :: %{required(String.t()) => term()}
  @type authorizer() :: :client_id | :client_email

  @type signed_policy() :: %{url: String.t(), fields: map()}

  @type common_option() ::
          {:method, http_verb()}
          | {:authorizer, authorizer()}
          | {:expires_in, non_neg_integer()}
          | {:bucket, String.t()}
          | {:path, String.t()}
          | {:key, String.t()}
          | {:utc_now, Calendar.datetime()}

  @type url_option() ::
          {:payload, String.t() | nil}
          | {:host, String.t()}
          | {:query, query()}
          | {:headers, headers()}

  @type post_policy_option() :: {:conditions, [condition()]} | {:fields, map()}

  @doc """
  Signs a POST policy

  Signed POST policies can be used to allow external parties limited upload access to a bucket. A
  [policy document](https://cloud.google.com/storage/docs/authentication/signatures#policy-document)
  can be used to limit in which bucket, with what key a file can be uploaded, and it supports
  setting file-size limits.

  [Google's documentation](https://cloud.google.com/storage/docs/xml-api/post-object-forms#usage_and_examples)
  describes how this can be used to perform a multipart upload.

  ## Options
    * `:bucket` - `String.t()` - The name of the GCS bucket.
    * `:key` - The key to the file in the bucket, without leading slash.
    * `:method` - The key to the file in the bucket, without leading slash. Default: `"GET"`
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
