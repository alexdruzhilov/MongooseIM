-module(mod_jingle2sip).
-behavior(gen_mod).

%% ----------------------------------------------------------------------
%% Exports

%% Client API

%% gen_mod handlers
-export([start/2, stop/1]).

%% ejabberd handlers
-export([handle_ejabberd_sm/3]).

%% ----------------------------------------------------------------------
%% Imports

-include("ejabberd.hrl").
-include("jlib.hrl").

%% VERSION defined both in ejabberd.hrl and nksip.hrl, so it's need to be fixed
-undef(VERSION).

-include_lib("exml/include/exml.hrl").
-include_lib("nksip/include/nksip.hrl").

%% ----------------------------------------------------------------------
%% gen_mod callbacks
%% Starting and stopping functions for users' archives

start(Host, Opts) ->
    start_nksip_server(),
    IQDisc = gen_mod:get_opt(iqdisc, Opts, one_queue),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_JINGLE, ?MODULE, handle_ejabberd_sm, IQDisc),
    ok.

stop(Host) ->
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_JINGLE),
    stop_nksip_server(),
    ok.

%% ----------------------------------------------------------------------
%% hooks and handlers

handle_ejabberd_sm(From, To, #iq{type = Type, lang = _Lang, sub_el = SubEl} = IQ) ->
    case {Type, SubEl} of
        {set, {xmlel, <<"jingle">>, _, _}} ->
            process_jingle_stanza(From, To, IQ);
        _ -> IQ
    end.

%% ----------------------------------------------------------------------
%% Internal functions

start_nksip_server() ->
    nksip_app:start(),
    nksip:start(server, mod_jingle2sip_sipapp_server, [server], 
        [
            {transport, {udp, any, 5070}}, 
            {transport, {tls, any, 5071}}
        ]).

stop_nksip_server() ->
    nksip:stop_all().

process_jingle_stanza(From, To, IQ) -> 
    Action = xml:get_tag_attr_s(<<"action">>, IQ#iq.sub_el),
    ?INFO_MSG("Jingle stanza with action '~s' received", [Action]),
    case Action of
        <<"session-initiate">> ->
            process_jingle_session_initiate(From, To, IQ);
        <<"transport-info">> ->
            process_jingle_transport_info(From, To, IQ);
        <<"session-accept">> ->
            process_jingle_session_accept(From, To, IQ);
        <<"session-terminate">> ->
            process_jingle_session_terminate(From, To, IQ);
        _ -> IQ
    end.

process_jingle_session_initiate(From, To, IQ) -> 
    Sender = jid_to_sip_uri(From),
    Receiver = jid_to_sip_uri(To),
    Sid = xml:get_tag_attr_s(<<"sid">>, IQ#iq.sub_el),
    Sdp = jingle_sdp:to_sdp(IQ#iq.sub_el),
    Result = nksip_uac:invite(server,  Receiver, [
        {from, Sender}, 
        {call_id, Sid}, 
        {body, Sdp}
    ]),
    case Result of
        {ok, 200, [{dialog_id, DialogId}]} -> 
            AckResult = nksip_uac:ack(server, DialogId, [{body, Sdp}]),
            IQ#iq{type = result};
        _ -> IQ
    end.

process_jingle_transport_info(_From, _To, IQ) -> IQ.

process_jingle_session_accept(_From, _To, IQ) -> IQ.

process_jingle_session_terminate(_From, _To, IQ) -> IQ.

jid_to_sip_uri(#jid{user = User, server = Server}) ->
    "sip:" ++ binary_to_list(User) ++ "@" ++ binary_to_list(Server).
