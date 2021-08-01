defmodule GCSSignTest do
  use ExUnit.Case, async: true

  @credentials Jason.decode!(File.read!("./gcp_test_key.json"))
  @fixtures Jason.decode!(File.read!("./test/fixtures.json"), keys: :atoms)

  describe "GCSSign.sign_url_v4/2" do
    test "defaults" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        utc_now: fixture_time()
      ]

      url = GCSSign.sign_url_v4(@credentials, sign_opts)
      uri = URI.parse(url)
      query = URI.decode_query(uri.query)

      assert url =~ ~r(^https://storage.googleapis.com/demo-bucket/test.txt)
      assert query["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert query["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert query["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)
      assert query["x-goog-expires"] == "3600"
      assert query["x-goog-signature"] == @fixtures.url_v4.defaults
      assert query["x-goog-signedheaders"] == "host"
    end

    test "custom expires_in" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        expires_in: 60,
        utc_now: fixture_time()
      ]

      url = GCSSign.sign_url_v4(@credentials, sign_opts)
      uri = URI.parse(url)
      query = URI.decode_query(uri.query)

      assert url =~ ~r(^https://storage.googleapis.com/demo-bucket/test.txt)
      assert query["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert query["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert query["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)
      assert query["x-goog-expires"] == "60"
      assert query["x-goog-signature"] == @fixtures.url_v4.custom_expires_in
      assert query["x-goog-signedheaders"] == "host"
    end

    test "custom cname" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        host: "cname.com",
        utc_now: fixture_time()
      ]

      url = GCSSign.sign_url_v4(@credentials, sign_opts)
      uri = URI.parse(url)
      query = URI.decode_query(uri.query)

      assert url =~ ~r(^https://cname.com/test.txt)
      assert query["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert query["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert query["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)
      assert query["x-goog-expires"] == "3600"
      assert query["x-goog-signature"] == @fixtures.url_v4.custom_cname
      assert query["x-goog-signedheaders"] == "host"
    end

    test "custom headers" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        headers: [{"x-custom-header", "value"}, {"x-custom-header", "value2"}],
        utc_now: fixture_time()
      ]

      url = GCSSign.sign_url_v4(@credentials, sign_opts)
      uri = URI.parse(url)
      query = URI.decode_query(uri.query)

      assert url =~ ~r(^https://storage.googleapis.com/demo-bucket/test.txt)
      assert query["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert query["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert query["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)
      assert query["x-goog-expires"] == "3600"
      assert query["x-goog-signature"] == @fixtures.url_v4.custom_headers
      assert query["x-goog-signedheaders"] == "host;x-custom-header"
    end
  end

  describe "GCSSign.sign_post_policy_v4/2" do
    test "defaults" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        utc_now: fixture_time()
      ]

      assert {:ok, policy} = GCSSign.sign_post_policy_v4(@credentials, sign_opts)
      assert policy.url == "https://storage.googleapis.com/demo-bucket"

      assert policy.fields["bucket"] == "demo-bucket"
      assert policy.fields["key"] == "test.txt"
      assert policy.fields["policy"] == @fixtures.post_policy_v4.defaults.policy
      assert policy.fields["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert policy.fields["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert policy.fields["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)
      assert policy.fields["x-goog-signature"] == @fixtures.post_policy_v4.defaults.signature
    end

    test "with custom conditions" do
      sign_opts = [
        bucket: "demo-bucket",
        key: "test.txt",
        conditions: [["content-length-range", "123", "1234"]],
        utc_now: fixture_time()
      ]

      assert {:ok, policy} = GCSSign.sign_post_policy_v4(@credentials, sign_opts)
      assert policy.url == "https://storage.googleapis.com/demo-bucket"

      assert policy.fields["bucket"] == "demo-bucket"
      assert policy.fields["key"] == "test.txt"
      assert policy.fields["policy"] == @fixtures.post_policy_v4.custom_conditions.policy
      assert policy.fields["x-goog-algorithm"] == "GOOG4-RSA-SHA256"
      assert policy.fields["x-goog-credential"] =~ ~r(^\d+/\d{8}/auto/storage/goog4_request$)
      assert policy.fields["x-goog-date"] =~ ~r(^\d{8}T\d{6}Z$)

      assert policy.fields["x-goog-signature"] ==
               @fixtures.post_policy_v4.custom_conditions.signature
    end
  end

  @fixture_time "2021-08-01T00:02:48.775114Z"
  defp fixture_time() do
    {:ok, time, 0} = DateTime.from_iso8601(@fixture_time)

    time
  end
end
