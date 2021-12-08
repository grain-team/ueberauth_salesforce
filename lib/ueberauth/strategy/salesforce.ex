defmodule Ueberauth.Strategy.Salesforce do
  @moduledoc """
  Salesforce Strategy for Überauth.
  """

  use Ueberauth.Strategy,
    uid_field: :sub,
    default_scope: "openid",
    hd: nil,
    userinfo_endpoint: "https://login.salesforce.com/services/oauth2/userinfo"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles initial request for Salesforce authentication.
  """
  def handle_request!(conn) do
    params =
      []
      |> with_optional(:scope, conn)
      |> with_optional(:immediate, conn)
      |> with_optional(:display, conn)
      |> with_optional(:login_hint, conn)
      |> with_optional(:prompt, conn)
      |> with_param(:scope, conn)
      |> with_param(:immediate, conn)
      |> with_param(:display, conn)
      |> with_param(:login_hint, conn)
      |> with_param(:prompt, conn)
      |> with_state_param(conn)

    opts = oauth_client_options_from_conn(conn)
    redirect!(conn, Ueberauth.Strategy.Salesforce.OAuth.authorize_url!(params, opts))
  end

  @doc """
  Handles the callback from Salesforce.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]
    opts = oauth_client_options_from_conn(conn)

    case Ueberauth.Strategy.Salesforce.OAuth.get_access_token(params, opts) do
      {:ok, token} ->
        fetch_user(conn, token)

      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:salesforce_user, nil)
    |> put_private(:salesforce_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.salesforce_user[uid_field]
  end

  @doc """
  Includes the credentials from the Salesforce response.
  """
  def credentials(conn) do
    token = conn.private.salesforce_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, " ")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token,
      other: %{instance_url: token.other_params["instance_url"]}
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.salesforce_user

    %Info{
      email: user["email"],
      first_name: user["givenName"],
      image: user["picture"],
      last_name: user["familyName"],
      name: user["name"],
      urls: user["urls"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Salesforce callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.salesforce_token,
        user: conn.private.salesforce_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :salesforce_token, token)

    # userinfo_endpoint from https://login.salesforce.com/.well-known/openid-configuration
    # the userinfo_endpoint may be overridden in options when necessary.
    resp = Ueberauth.Strategy.Salesforce.OAuth.get(token, get_userinfo_endpoint(conn))

    case resp do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        put_private(conn, :salesforce_user, user)

      {:error, %OAuth2.Response{status_code: status_code}} ->
        set_errors!(conn, [error("OAuth2", status_code)])

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp get_userinfo_endpoint(conn) do
    case option(conn, :userinfo_endpoint) do
      {:system, varname, default} ->
        System.get_env(varname) || default

      {:system, varname} ->
        System.get_env(varname) || Keyword.get(default_options(), :userinfo_endpoint)

      other ->
        other
    end
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
