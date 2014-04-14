-module(mod_jingle2sip_sipapp_server).

-behaviour(nksip_sipapp).
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2013 Carlos Gonzalez Florido.  All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%% @doc SipApp Tutorial server callback module implementation.
%%
%% This modules implements a proxy server callback module for NkSIP Tutorial.
%% It allows any request from any user in domain "nksip", having password "1234".
%% Requests without user and domain "nksip" are processed internally (i.e. "sip:nksip").
%% Request with user and domain "nksip" are found (as a registrar) and proxied.
%% Other requests are proxied to the same origin Request-URI

-export([init/1, get_user_pass/3, authorize/4, route/6, invite/3, reinvite/3, cancel/2, 
         ack/3, bye/3, options/3, register/3, info/3]).
-export([ping_update/3, register_update/3, dialog_update/3, session_update/3]).
-export([handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include_lib("nksip/include/nksip.hrl").


%% ===================================================================
%% Callbacks
%% ===================================================================

-record(state, {
    id,
    started
}).

%% @doc SipApp intialization.
init([Id]) ->
    {ok, #state{id=Id, started=httpd_util:rfc1123_date()}}.


%% @doc Called when the SipApp is stopped.
terminate(_Reason, _State) ->
    ok.


%% @doc Called to check a user password for a realm.
%% When a request is received containing a `Authorization' or `Proxy-Authorization' 
%% header, this function is called by NkSIP including the header's `User' and `Realm', 
%% to check if the authorization data in the header corresponds to the user's password.
%%
%% You should normally reply with the user's password (if you have it for this user 
%% and realm). NkSIP will use the password and the digest information in the header 
%% to check if it is valid, offering this information in the call to 
%% {@link authorize/4}. 
%%
%% You can also reply `true' if you want to accept any request from this user 
%% without checking any password, or `false' if you don't have a password for this user 
%% or want her blocked.
%%
%% If you don't want to store <i>clear-text</i> passwords of your users, 
%% you can use {@link nksip_auth:make_ha1/3} to generate a <i>hash</i> of the password 
%% for an user and a realm, and store only this hash instead of the real password. 
%% Later on you can reply here with the hash instead of the real password.
%%
%% If you don't define this function, NkSIP will reply with password `<<>>' 
%% if user is `anonymous', and `false' for any other user.  
%%
get_user_pass(<<"anonymous">>, _, State) ->
    {reply, <<>>, State};
get_user_pass(_User, _Realm, State) ->
    {reply, false, State}.



%% @doc Called for every incoming request to be authorized or not.
%%
%% If `ok' is replied the request is authorized and the 
%% request processing continues. If `authenticate' is replied, the request will be 
%% rejected (statelessly) with a 401 <i>Unauthorized</i>. 
%% The other party will usually send the request again, this time with an 
%% `Authorization' header. If you reply `proxy_authenticate', it is rejected 
%% with a 407 <i>Proxy Authentication Rejected</i> response and the other party 
%% will include a `Proxy-Authorization' header.
%%
%% You can use the tags included in `AuthList' in order to decide to authenticate
%% or not the request.  AuthList includes the following tags:
%% <ul>
%%    <li>`dialog': the request is in-dialog and coming from the same ip and port
%%        than the last request for an existing dialog.</li>
%%    <li>`register': the request comes from the same ip, port and transport of a 
%%        currently valid registration (and the method is not <i>REGISTER</i>).</li>
%%    <li>`{{digest, Realm}, true}': there is at least one valid user authenticated
%%        (has a correct password) with this Realm.</li>
%%    <li>`{{digest, Realm}, false}': there is at least one user offering an 
%%        authentication header for this Realm, but all of them 
%%        have failed the authentication (no password was valid). </li>
%% </ul>
%%
%% You will usually want to combine these strategies. Typically you will first 
%% check using SIP digest authentication, and, in case of faillure, you can use 
%% previous registration and/or dialog authentication. 
%% If you don't define this function all requests will be authenticated.
%%
authorize(_AuthList, _ReqId, _From, State) ->
    {reply, ok, State}.


%% @doc This function is called by NkSIP for every new request, to check if it must be 
%% proxied, processed locally or replied immediately. For convenience, the scheme, user
%% and domain parts of the <i>Request-Uri</i> are included.
%%
%% If we want to <b>act as a proxy</b> and route the request, and we are not responsible 
%% for `Domain' we must return `proxy' or `{proxy, ruri, ProxyOpts}'. 
%% We must not return an `UriSet' in this case. 
%% NkSIP will then make additional checks to the request (like inspecting the 
%% `Proxy-Require' header) and will route it statefully to the same `Request-URI' 
%% contained in the request.
%%
%% If we are the resposible proxy for `Domain' we can provide a new list 
%% of URIs to route the request to. NkSIP will use <b><i>serial</i> and/or 
%% <i>parallel</i> forking</b> depending on the format of `UriSet'. 
%% If `UriSet' is a simple Erlang array of binaries representing uris, NkSIP will try 
%% each one serially. If any of the elements of the arrary is in turn a new array 
%% of binaries, it will fork them in parallel. 
%% For example, for  ```[ <<"sip:aaa">>, [<<"sip:bbb">>, <<"sip:ccc">>], <<"sip:ddd">>]'''
%% NkSIP will first forward the request to `aaa'. If it does not receive a successful 
%% (2xx) response, it will try `bbb' and `cccc' in parallel. 
%% If no 2xx is received again, `ddd' will be tried. See {@link nksip_registrar}
%% to find out how to get the registered contacts for this `Request-Uri'.
%%
%% Available options for `ProxyOpts' are:
%% <ul>
%%  <li>`stateless': Use it if you want to proxy the request <i>statelessly</i>. 
%%       Only one URL is allowed in `UriSet' in this case.</li>
%%  <li>`record_route': NkSIP will insert a <i>Record-Route</i> header before sending 
%%      the request, so that following request inside the dialog will be routed 
%%      to this proxy.</li>
%%  <li>`follow_redirects': If any 3xx response is received, the received contacts
%%      will be inserted in the list of uris to try.</li>
%%  <li><code>{route, {@link nksip:user_uri()}}</code>: 
%%      NkSIP will insert theses routes as <i>Route</i> headers
%%      in the request, before any other existing `Route' header.
%%      The request would then be sent to the first <i>Route</i>.</li>
%%  <li><code>{headers, [{@link nksip:header()}]}</code>: 
%%      Inserts these headers before any existing header.</li>
%%  <li>`remove_routes': Removes any previous <i>Route</i> header in the request.
%%      A proxy should not usually do this. Use it with care.</li>
%%  <li>`remove_headers': Remove previous non-vital headers in the request. 
%%      You can use modify the headers and include them with using `{headers, Headers}'. 
%%      A proxy should not usually do this. Use it with care.</li>
%% </ul>
%% 
%% If we want to <b>act as an endpoint or B2BUA</b> and answer to the request 
%% from this SipApp, we must return `process' or `{process, ProcessOpts}'. 
%% NkSIP will then make additional checks to the request (like inspecting 
%% `Require' header), start a new transaction and call the function corresponding 
%% to the method in the request (like `invite/3', `options/3', etc.)
%%
%% Available options for `ProcessOpts' are:
%% <ul>
%%  <li>`stateless': Use it if you want to process this request <i>statelessly</i>. 
%%       No transaction will be started.</li>
%% <li><code>{headers, [{@link nksip:header()}]}</code>: 
%%     Insert these headers before any existing header, before calling the next 
%%     callback function.</li>
%% </ul>
%%
%% We can also <b>send a reply immediately</b>, replying `{response, Response}', 
%% `{response, Response, ResponseOpts}' or simply `Response'. See {@link nksip_reply} 
%% to find the recognized response values. The typical reason to reply a response here 
%% is to send <b>redirect</b> or an error like `not_found', `ambiguous', 
%% `method_not_allowed' or any other. If the form `{response, Response}' or 
%% `{response, Response, ResponseOpts}' is used the response is sent statefully, 
%% and a new transaction will be started, unless `stateless' is present in `ResponseOpts'.
%% If simply `Response' is used no transaction will be started. 
%% The only recognized option in `ResponseOpts' is `stateless'.
%%
%% If route/3 is not defined the default reply would be `process'.
%%
-type route_reply() ::
    proxy | {proxy, ruri | nksip:uri_set()} | 
    {proxy, ruri | nksip:uri_set(), nksip_lib:proplist()} | 
    process | {process, nksip_lib:proplist()} |
    {response, nksip:sipreply()} | 
    {response, nksip:sipreply(), nksip_lib:proplist()}.

route(_Scheme, _User, _Domain, _ReqId, _From, State) ->
    io:format("!!!!!!!! Route ~p~n ~p~n ~p~n ~p~n ~p~n ~p~n", [_Scheme, _User, _Domain, _ReqId, _From, State]),
    {reply, process, State}.


%% @doc This function is called by NkSIP to process a new INVITE request as an endpoint.
%% Before replying a final response, you will usually call 
%% {@link nksip_request:reply/3} to send a provisional response like 
%% `ringing' (which would send a 180 <i>Ringing</i> reply).
%%
%% If a quick response (like `busy') is not going to be sent immediately 
%% (which is typical for INVITE requests, as the user would normally need to accept 
%% the call) you must return `{noreply, NewState}' and spawn a new process, 
%% calling {@link nksip:reply/2} from the new process, in order to avoid 
%% blocking the SipApp process.
%%
%% You can access the body of the request by calling {@link nksip_request:body/2}. 
%% INVITE requests will usually have a SDP body. If this is the case, and the 
%% `Content-Type' header contains `application/sdp', NkSIP will decode the SDP and 
%% `nksip_request:body/2' will return a {@link nksip_sdp:sdp()} object you can manage 
%% with the functions in {@link nksip_sdp}. 
%% If it is not recognized it would return a binary, or `<<>>' if it is missing.
%%
%% You must then answer the request. The possible responses are defined in 
%% {@link nksip_reply}.
%% If a successful (2xx) response is sent, you should include a new generated SDP body
%% in the response. A new dialog will then start. 
%% The remote party should then send an ACK request immediately.
%% If none is received, NkSIP will automatically stop the dialog.
%%
invite(_ReqId, _From, State) ->
    io:format("!!!!!!!! Invite ~p~n ~p~n ~p~n", [_ReqId, _From, State]),
    {reply, decline, State}.


%% @doc This function is called when a new in-dialog INVITE request is received.
%% The guidelines in {@link invite/4} are valid, but you shouldn't send provisional
%% responses, but a final response inmediatly.
%% 
%% If the dialog's target or the SDP session parameters are updated by the request or
%% its response, {@link dialog_update/3} and/or {@link session_update/3} would be
%% called.
%%
reinvite(_ReqId, _From, State) ->
    {reply, decline, State}.


%% @doc Called when a pending INVITE request is cancelled.
%% When a CANCEL request is received by NkSIP, it will check if it belongs to an 
%% existing INVITE transaction. If not, a 481 <i>Call/Transaction does not exist</i> 
%% will be automatically replied.
%%
%% If it belongs to an existing INVITE transaction, NkSIP replies 200 <i>OK</i> to the
%% CANCEL request. If the matching INVITE transaction has not yet replied a
%% final response, NkSIP replies it with a 487 (Request Terminated) and this function
%% is called. If a final response has already beeing replied, it has no effect.
%%
cancel(_ReqId, State) ->
    {noreply, State}.


%% @doc Called when a valid ACK request is received.
%%
%% This function is called by NkSIP when a new valid in-dialog ACK request has to
%% be processed locally.
%% You don't usually need to implement this callback. One possible reason to do it is 
%% to receive the SDP body from the other party in case it was not present in the INVITE
%% (you can also get it from the {@link session_update/3} callback).
%%
ack(_ReqId, _From, State) ->
    io:format("!!!!!!!! Ack ~p~n ~p~n ~p~n", [_ReqId, _From, State]),
    {reply, ok, State}.


%% @doc Called when a valid BYE request is received.
%% When a BYE request is received, NkSIP will automatically response 481 
%% <i>Call/Transaction does not exist</i> if it doesn't belong to a current dialog.
%% If it does, NkSIP stops the dialog and this callback functions is called.
%% You won't usually need to implement this function, but in case you do, you
%% should reply `ok' to send a 200 response back.
%%
bye(_ReqId, _From, State) ->
    {reply, ok, State}.


%% @doc Called when a valid INFO request is received.
%% When an INFO request is received, NkSIP will automatically response 481
%% <i>Call/Transaction does not exist</i> if it doesn't belong to a current dialog.
%% If it does, NkSIP this callback functions is called.
%% If implementing this function, you should reply `ok' to send a 200 response back.
%%
info(_ReqId, _From, State) ->
  {reply, ok, State}.


%% @doc Called when a OPTIONS request is received.
%% This function is called by NkSIP to process a new incoming OPTIONS request as 
%% an endpoint. If not defined, NkSIP will reply with a 200 <i>OK</i> response, 
%% including automatically generated `Allow', `Accept' and `Supported' headers.
%%
%% NkSIP will not send any body in its automatic response. This is ok for proxies. 
%% If you are implementing an endpoint or B2BUA, you should implement this function 
%% and include in your response a SDP body representing your supported list of codecs, 
%% and also `Allow', `Accept' and `Supported' headers.
%%
options(_ReqId, _From, State) ->
    Reply = {ok, [], <<>>, [make_contact, make_allow, make_accept, make_supported]},
    {reply, Reply, State}.


%% @doc This function is called by NkSIP to process a new incoming REGISTER request. 
%% If it is not defined, but `registrar' option was present in the SipApp's 
%% startup config, NkSIP will process the request. 
%% It will NOT check if <i>From</i> and <i>To</i> headers contains the same URI,
%% or if the registered domain is valid or not. If you need to check this,
%% implement this function returning `register' if everything is ok.
%% See {@link nksip_registrar} for other possible response codes defined in the SIP 
%% standard registration process.
%%
%% If this function is not defined, and no `registrar' option is found, 
%% a 405 <i>Method not allowed</i> would be replied. 
%%
%% You should define this function in case you are implementing a registrar server 
%% and need a specific REGISTER processing 
%% (for example to add some headers to the response).
%%
register(_ReqId, _From, State) ->
    %% NOTE: In this default implementation, State contains the SipApp options.
    %% If you implement this function, State will contain your own state.
    Reply = case lists:member(registrar, State) of
        true -> register;
        false -> {method_not_allowed, ?ALLOW}
    end,
    {reply, Reply, State}.


%% @doc Called when a dialog has changed its state.
%%
%% A new dialog will be created when you send an INVITE request 
%% (using {@link nksip_uac:invite/3}) and a successful (101-299) response is received, 
%% or after an INVITE is received and the call to `invite/3' callback replies 
%% with a successful response. If the response is provisional (101-199) the dialog 
%% will be marked as temporary or <i>early</i>, waiting for the final response 
%% to be confirmed or deleted.
%%
%% The dialog is destroyed when a valid in-dialog BYE request is sent or received 
%% (and for many other reasons, see {@link nksip_dialog:stop_reason()}). 
%%
%% Once the dialog is established, some in-dialog methods (like INVITE) can update the
%% `target' of the dialog. 
%%
%% NkSIP will call this function every time a dialog is created, its target is updated
%% or it is destroyed.
%%
dialog_update(_DialogId, _Status, State) ->
    io:format("!!!!!!!! Dialog update ~p~n ~p~n ~p~n", [_DialogId, _Status, State]),
    {noreply, State}.


%% @doc Called when a dialog has updated its SDP session parameters.
%% When NkSIP detects that, inside an existing dialog, both parties have agreed on 
%% a specific SDP defined session, it will call this function.
%% You can use the functions in {@link nksip_sdp} to process the SDP data.
%%
%% This function will be also called after each new successful SDP negotiation.
%%
session_update(_DialogId, _Status, State) ->
    io:format("!!!!!!!! Session update ~p~n ~p~n ~p~n", [_DialogId, _Status, State]),
    {noreply, State}.


%% @doc Called when the status of an automatic ping configuration changes.
%% See {@link nksip_sipapp_auto:start_ping/5}.
ping_update(_PingId, _OK, State) ->
    {noreply, State}.


%% @doc Called when the status of an automatic registration configuration changes.
%% See {@link nksip_sipapp_auto:start_register/5}.
register_update(_RegId, _OK, State) ->
    {noreply, State}.


%% @doc Called when a direct call to the SipApp process is made using 
%% {@link nksip:call/2} or {@link nksip:call/3}.
handle_call(_Msg, _From, State) ->
    {error, unexpected_call, State}.


%% @doc Called when a direct cast to the SipApp process is made using 
%% {@link nksip:cast/2}.
handle_cast(_Msg, State) ->
    {error, unexpected_cast, State}.


%% @doc Called when the SipApp process receives an unknown message.
handle_info(_Msg, State) ->
    {noreply, State}.









