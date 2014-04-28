-module(mod_jingle2sip_proxy).

%% ----------------------------------------------------------------------
%% Exports

-export([]).

%% ----------------------------------------------------------------------
%% Imports

%% ----------------------------------------------------------------------
%% Proxy methods

jingle2sip(From, To, Iq) -> 
    FromUri = jid_to_uri(From),
    ToUri = jid_to_uri(To),
    CallId = xml:get_tag_attr_s(<<"sid">>, Iq#iq.sub_el),
    case xml:get_tag_attr_s(<<"action">>, IQ#iq.sub_el) of
        <<"session-initiate">> ->
            nksip_uac:invite(sip_server, ToUri, [
                {from, FromUri}, 
                {call_id, CallId}, 
                {body, jingle_sdp:to_sdp(Iq#iq.sub_el)}
            ]);
        <<"session-terminate">> ->
            [DialogId | _] = nksip_dialog:get_all(sip_server, CallId),
            if 
                DialogId =:= undefined ->
                    nksip_uac:bye(sip_server, DialogId, [
                        {from, Sender}, 
                        {call_id, Sid}
                    ]);
                true -> ok
            end;
        _ -> ok
    end.

sip2jingle() -> ok.

%% ----------------------------------------------------------------------
%% Jingle protocol methods

jingle_session_accept(From, To, Sid, Body) -> 
    Iq = mod_jingle2sip_utils:create_jingle_iq(Sid, [
        {<<"action">>, <<"session-accept">>},
        {<<"initiator">>, jlib:jid_to_binary(From)},
        {<<"responder">>, jlib:jid_to_binary(To)},
    ], Body#xmlel.children),
    ejabberd_local:route_iq(From, To, Iq, fun(Response) -> end).

jingle_session_terminate(From, To, Sid, Reason) ->
    Children = 
        case Reason of
            undefined -> [];
            _ -> [#xmlel {
                name = <<"success">>,
                children = [
                    #xmlel{
                        name = <<"text">>,
                        children = [#xmlcdata{content = atom_to_binary(Reason)}]
                    }
                ]
            }]
        end,
    Iq = mod_jingle2sip_utils:create_jingle_iq(Sid, [
        {<<"action">>, <<"session-terminate">>}
    ], Children),
    ejabberd_local:route_iq(From, To, Iq, fun(Response) -> end).

%% ----------------------------------------------------------------------
%% SIP protocol methods


%% ----------------------------------------------------------------------
%% Helpers

jid2uri(#jid{user = User, server = Server, resource = Resource}) ->
    Uri = "sip:" ++ binary_to_list(User) ++ "@" ++ binary_to_list(Server),
    if
        Resource =/= <<>> ->
            Uri ++ "/" ++ binary_to_list(Resource);
        true -> Uri
    end.

uri2jid(#uri{user = User, domain = Domain, resource = Resource}) ->
    #jid{
        user       = User,
        server     = Domain,
        resource   = Resource,
        luser      = User,
        lserver    = Domain,
        lresource  = Resource
    };

uri2jid(Value) when is_binary(Value) orelse when is_list(Value) ->
    [Uri | _] = nksip_parse_uri:uris(Value),
    uri2jid(Uri).

