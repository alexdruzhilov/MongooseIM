-module(mod_jingle2sip_utils).

%% ----------------------------------------------------------------------
%% Exports

-export([uri_to_jid/1, jid_to_uri/1]).

%% ----------------------------------------------------------------------
%% Imports

-include("jlib.hrl").
-include_lib("nksip/include/nksip.hrl").

%% ----------------------------------------------------------------------
%% Public methods

jid_to_uri(#jid{user = User, server = Server, resource = Resource}) ->
    Uri = "sip:" ++ binary_to_list(User) ++ "@" ++ binary_to_list(Server),
    if
        Resource =/= <<>> ->
            Uri ++ "/" ++ binary_to_list(Resource);
        true -> Uri
    end.

uri_to_jid(#uri{user = User, domain = Domain, resource = Resource}) ->
    #jid{
        user       = User,
        server     = Domain,
        resource   = Resource,
        luser      = User,
        lserver    = Domain,
        lresource  = Resource
    };

uri_to_jid(Bin) when is_binary(Bin) ->
    [Uri | _] = nksip_parse_uri:uris(Bin),
    uri_to_jid(Uri).
