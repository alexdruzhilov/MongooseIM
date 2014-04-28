-module(jingle_sdp).

%% ----------------------------------------------------------------------
%% Exports

-export([to_sdp/1, from_sdp/2]).

%% ----------------------------------------------------------------------
%% Imports

-include("jlib.hrl").

-include_lib("nksip/include/nksip.hrl").


%% ===================================================================
%% From SDP to Jingle SDP    
%% ===================================================================

to_sdp(#xmlel{} = Jingle) -> 
    Sdp = #sdp{
        sdp_vsn = <<"0">>,
        user = "-",
        id = 1923518516, % may be needs random nubmer,
        vsn = 2,
        address = {<<"IN">>, <<"IP4">>, <<"0.0.0.0">>},
        session = <<"-">>,
        time = [{0, 0, []}]
    },
    Sdp1 = parse_groups(Jingle, Sdp),
    parse_contents(Jingle, Sdp1).

parse_groups(Jingle, Sdp) ->
    [Group | _] = [El || #xmlel{name = <<"group">>} = El <- Jingle#xmlel.children],
    if 
        Group =/= [] -> parse_group(Group, Sdp);
        true -> Sdp
    end.

parse_group(Group, #sdp{attributes = Attrs} = Sdp) ->
    Namespace = xml:get_tag_attr_s(<<"xmlns">>, Group),
    Contents = [xml:get_tag_attr_s(<<"name">>, Content) || 
        #xmlel{name = <<"content">>} = Content <- Group#xmlel.children],
    Attr = 
        case Namespace of
            <<"urn:xmpp:jingle:apps:grouping:0">> -> {<<"group">>, [
                    case xml:get_tag_attr_s(<<"semantics">>, Group) of
                        false -> xml:get_tag_attr_s(<<"type">>, Group);
                        Semantics -> Semantics
                    end
                    | Contents
                ]};
            <<"urn:ietf:rfc:5888">> -> {<<"group">>, [
                    xml:get_tag_attr_s(<<"type">>, Group) | Contents
                ]}
        end,
    Sdp#sdp{attributes = [Attr | Attrs]}.

parse_contents(Jingle, Sdp) ->
    ContentElements = [El || #xmlel{name = <<"content">>} = El <- Jingle#xmlel.children],
    lists:foldl(
            fun(Element, SdpMacc) ->
                parse_content(Element, SdpMacc)
            end, Sdp, ContentElements).

parse_content(Content, #sdp{medias = Medias} = Sdp) ->
    Senders = xml:get_tag_attr_s(<<"senders">>, Content),
    Name = xml:get_tag_attr_s(<<"name">>, Content),
    Description = xml:get_subtag(Content, <<"description">>),
    Transport = xml:get_subtag(Content, <<"transport">>),
    Fingerprint = xml:get_subtag(Transport, <<"fingerprint">>),
    Encryption = xml:get_subtag(Description, <<"encryption">>),
    Media = xml:get_tag_attr_s(<<"media">>, Description),
    Port = 
        case Senders of
            <<"rejected">> -> 0;
            _              -> 1
        end,
    Proto = 
        if
            Fingerprint =/= false orelse Encryption =/= false -> <<"RTP/SAVPF">>;
            true                                              -> <<"RTP/AVPF">>
        end,
    Mode = senders2mode(Senders),
    SdpM = #sdp_m{
        media = Media,
        port = Port, 
        proto = Proto,
        connect = {<<"IN">>, <<"IP4">>, <<"0.0.0.0">>},
        attributes = [
            {<<"rtcp">>, [<<"1">>, <<"IN">>, <<"IP4">>, <<"0.0.0.0">>]}
        ]
    },
    SdpM1 = parse_content_transport(Transport, SdpM),
    SdpM2 = SdpM1#sdp_m{
        attributes = SdpM1#sdp_m.attributes ++ [
            {<<"mid">>,  [Name]},
            {Mode, []}
        ]
    },
    SdpM3 = parse_content_description(Description, SdpM2),
    SdpM4 = parse_content_transport_candidates(Transport, SdpM3),
    Sdp#sdp{medias = Medias ++ [SdpM4]}.

parse_content_description(Description, SdpM) ->
    RtcpMux = xml:get_subtag(Description, <<"rtcp-mux">>),
    Encryption = xml:get_subtag(Description, <<"encryption">>),
    Crypto = xml:get_subtag(Encryption, <<"crypto">>),
    RtpHdrext = xml:get_subtag(Description, <<"rtp-hdrext">>),
    Source = xml:get_subtag(Description, <<"source">>),
    Ssrc = xml:get_subtag(Description, <<"ssrc">>),
    PayloadTypes = [El || #xmlel{name = <<"payload-type">>} = El <- Description#xmlel.children],
    Fmt = [xml:get_tag_attr_s(<<"id">>, PayloadType) || PayloadType <- PayloadTypes],
    SsrcValue = xml:get_tag_attr_s(<<"ssrc">>, Description),
    RtcpMuxAttr = 
        if 
            RtcpMux =/= false -> [{<<"rtcp-mux">>, []}];
            true -> []
        end,
    SdpM1 = 
        if 
            RtpHdrext =/= false ->
                parse_content_description_rtp_hdrext(RtpHdrext, SdpM);
            true ->
                SdpM
        end,
    SdpM2 = SdpM1#sdp_m{
        fmt = Fmt,
        attributes = SdpM1#sdp_m.attributes ++ RtcpMuxAttr
    },
    SdpM3 = parse_content_description_crypto(Crypto, SdpM2),
    SdpM4 =
        if
            Source =:= false andalso Ssrc =/= false ->
                parse_content_description_ssrc(Ssrc, SsrcValue, SdpM3);
            true ->
                SdpM3
        end,
    SdpM5 = lists:foldl(
            fun(El, SdpMacc) ->
                parse_content_description_payload(El, SdpMacc)
            end, SdpM4, PayloadTypes),
     SdpM6 =
        if
            Source =/= false ->
                parse_content_description_source(Source, SdpM5);
            true ->
                SdpM5
        end,
    parse_content_description_payload_rtcp_fb(Description, SdpM6).

parse_content_description_crypto(Crypto, #sdp_m{attributes = Attrs} = SdpM) ->
    CryptoAttrs = [
        xml:get_tag_attr_s(<<"tag">>, Crypto), 
        xml:get_tag_attr_s(<<"crypto-suite">>, Crypto),
        xml:get_tag_attr_s(<<"key-params">>, Crypto)
        | 
            case xml:get_tag_attr_s(<<"session-params">>, Crypto) of
                false -> [];
                SessionParams -> [SessionParams]
            end
        ],
    SdpM#sdp_m{
        attributes = Attrs ++ [{<<"crypto">>, CryptoAttrs}]
    }.

parse_content_description_payload(Payload, #sdp_m{attributes = Attrs} = SdpM) ->
    Id = xml:get_tag_attr_s(<<"id">>, Payload),
    Name = xml:get_tag_attr_s(<<"name">>, Payload),
    Clockrate = xml:get_tag_attr_s(<<"clockrate">>, Payload),
    Channels = xml:get_tag_attr_s(<<"channels">>, Payload),
    FmtpList = [parse_content_description_payload_parameter(El) || 
        #xmlel{name = <<"parameter">>} = El <- Payload#xmlel.children],
    RtpMapValue = erlang:iolist_to_binary(
        [
            Name, <<"/">>, Clockrate 
            | 
            if 
                Channels =/= false andalso Channels =/= <<"1">> -> [<<"/">>, Channels]; 
                true -> []
            end
        ]
    ),
    Fmtp = 
        if 
            FmtpList =/= [] ->
                [{<<"fmtp">>, [Id | FmtpList]}];
            true ->
                []
        end,
    SdpM1 = SdpM#sdp_m{
        attributes = Attrs ++ [{<<"rtpmap">>, [Id, RtpMapValue]} | Fmtp]
    },
    parse_content_description_payload_rtcp_fb(Payload, SdpM1).

parse_content_description_payload_parameter(Parameter) ->
    Name = xml:get_tag_attr_s(<<"name">>, Parameter),
    Value = xml:get_tag_attr_s(<<"value">>, Parameter),
    if
        Name =/= false -> <<Name/binary, "=", Value/binary>>;
        true -> Value
    end.

parse_content_description_payload_rtcp_fb(Element, SdpM) ->
    RtcpFbTrrInt = xml:get_subtag(Element, <<"rtcp-fb-trr-int">>),
    SdpM1 = 
        if
            RtcpFbTrrInt =/= false ->
                RtcpFbTrrIntValue = 
                    case xml:get_tag_attr_s(<<"value">>, RtcpFbTrrInt) of
                        false -> <<"0">>;
                        Value -> Value
                    end,
                SdpM#sdp_m{
                    attributes = SdpM#sdp_m.attributes ++ [
                        {<<"rtcp-fb">>, [<<"*">>, <<"trr-int">>, RtcpFbTrrIntValue]}
                    ]
                };
            true ->
                SdpM
        end,
    Id = 
        case xml:get_tag_attr_s(<<"id">>, Element) of
            false -> <<"*">>;
            IdValue -> IdValue
        end,
    RtcpFbs = [El || #xmlel{name = <<"rtcp-fb">>} = El <- Element#xmlel.children],
    lists:foldl(
        fun(RtcpFb, SdpMacc) ->
            Type = xml:get_tag_attr_s(<<"type">>, RtcpFb),
            SubType = 
                case xml:get_tag_attr_s(<<"subtype">>, RtcpFb) of
                    false -> [];
                    SubTypeValue -> [SubTypeValue]
                end,
            SdpMacc#sdp_m{
                attributes = SdpMacc#sdp_m.attributes ++ [
                    {<<"rtcp-fb">>, [Id, Type | SubType]}
                ]
            }
        end, SdpM1, RtcpFbs).

parse_content_description_rtp_hdrext(RtpHdrext, #sdp_m{attributes = Attrs} = SdpM) ->
    Id = xml:get_tag_attr_s(<<"id">>, RtpHdrext),
    Uri = xml:get_tag_attr_s(<<"uri">>, RtpHdrext),
    SdpM#sdp_m{attributes = Attrs ++ [{<<"extmap">>, [Id, Uri]}]}.

parse_content_description_source(Source, SdpM) ->
    Ssrc = xml:get_tag_attr_s(<<"ssrc">>, Source),
    Parameters = [El || #xmlel{name = <<"parameter">>} = El <- Source#xmlel.children],
    lists:foldl(
        fun(Parameter, #sdp_m{attributes = Attrs} = SdpMacc) ->
            Name = xml:get_tag_attr_s(<<"name">>, Parameter),
            Value = xml:get_tag_attr_s(<<"value">>, Parameter),
            Text = 
                if
                    Value =/= false andalso Value =/= [] -> <<Name/binary, ":", Value/binary>>;
                    true -> Name
                end,
            SdpMacc#sdp_m{
                attributes = Attrs ++ [
                    {<<"ssrc">>, [Ssrc, Text]}
                ]
            }
        end, SdpM, Parameters).

parse_content_description_ssrc(Ssrc, SsrcValue, #sdp_m{attributes = Attrs} = SdpM) ->
    Cname = xml:get_tag_attr_s(<<"cname">>, Ssrc),
    Msid = xml:get_tag_attr_s(<<"msid">>, Ssrc),
    Mslabel = xml:get_tag_attr_s(<<"mslabel">>, Ssrc),
    Label = xml:get_tag_attr_s(<<"label">>, Ssrc),
    SdpM#sdp_m{
        attributes = Attrs ++ [
            {<<"ssrc">>, [SsrcValue, <<"cname:", Cname/binary>>]},
            {<<"ssrc">>, [SsrcValue, <<"msid:", Msid/binary>>]},
            {<<"ssrc">>, [SsrcValue, <<"mslabel:", Mslabel/binary>>]},
            {<<"ssrc">>, [SsrcValue, <<"label:", Label/binary>>]}
        ]
    }.

parse_content_transport(Transport, #sdp_m{attributes = Attrs} = SdpM) ->
    Fingerprint = xml:get_subtag(Transport, <<"fingerprint">>),
    Ufrag = 
        if 
            Transport =/= false -> xml:get_tag_attr_s(<<"ufrag">>, Transport)
        end,
    Pwd = 
        if 
            Transport =/= false -> xml:get_tag_attr_s(<<"pwd">>, Transport)
        end,
    SdpM1 = SdpM#sdp_m{attributes = Attrs ++ [
        {<<"ice-ufrag">>, [Ufrag]},
        {<<"ice-pwd">>, [Pwd]}
    ]},
    if 
        Fingerprint =/= false ->
            parse_content_transport_fingerprint(Fingerprint, SdpM1);
        true -> 
            SdpM1
    end.

parse_content_transport_candidates(Transport, SdpM) ->
    Candidates = [El || #xmlel{name = <<"candidate">>} = El <- Transport#xmlel.children],
    lists:foldl(
            fun(El, SdpMacc) ->
                parse_content_transport_candidate(El, SdpMacc)
            end, SdpM, Candidates).

parse_content_transport_candidate(Candidate, #sdp_m{attributes = Attrs} = SdpM) ->
    Foundation = xml:get_tag_attr_s(<<"foundation">>, Candidate),
    Component = xml:get_tag_attr_s(<<"component">>, Candidate),
    Protocol = xml:get_tag_attr_s(<<"protocol">>, Candidate),
    Priority = xml:get_tag_attr_s(<<"priority">>, Candidate),
    Ip = xml:get_tag_attr_s(<<"ip">>, Candidate),
    Port = xml:get_tag_attr_s(<<"port">>, Candidate),
    Type = xml:get_tag_attr_s(<<"type">>, Candidate),
    RelAddr = xml:get_tag_attr_s(<<"rel-addr">>, Candidate),
    RelPort = xml:get_tag_attr_s(<<"rel-port">>, Candidate),
    Generation = 
        case xml:get_tag_attr_s(<<"generation">>, Candidate) of
            false -> <<"0">>;
            Gen -> Gen
        end,
    RelayList = 
        case Type of
            A when A =:= <<"srflx">> orelse A =:= <<"prflx">> orelse A =:= <<"relay">> -> 
                if
                    RelAddr =/= false andalso RelPort =/= false ->
                        [<<"raddr">>, RelAddr, <<"rport">>, RelPort];
                    true -> []
                end;
            _ -> []
        end,
    SdpM#sdp_m{
        attributes = Attrs ++ [
            {<<"candidate">>, [
                Foundation, 
                Component, 
                Protocol, 
                Priority, 
                Ip, 
                Port, 
                <<"typ">>, 
                Type
            ] ++ RelayList ++ [
                <<"generation">>,
                Generation
            ]}
        ]
    }.

parse_content_transport_fingerprint(Fingerprint, #sdp_m{attributes = Attrs} = SdpM) ->
    Hash = xml:get_tag_attr_s(<<"hash">>, Fingerprint),
    Text = xml:get_tag_cdata(Fingerprint),
    Setup = 
        case xml:get_tag_attr_s(<<"setup">>, Fingerprint) of
            false -> [];
            Value -> [{<<"setup">>, [Value]}]
        end,
    SdpM#sdp_m{
        attributes = Attrs ++ [{<<"fingerprint">>, [Hash, Text]} | Setup]
    }.

senders2mode(<<"initiator">>) -> <<"sendonly">>;
senders2mode(<<"responder">>) -> <<"recvonly">>;
senders2mode(<<"none">>)      -> <<"inactive">>;
senders2mode(<<"both">>)      -> <<"sendrecv">>.

mode2senders(<<"sendonly">>) -> <<"initiator">>;
mode2senders(<<"recvonly">>) -> <<"responder">>;
mode2senders(<<"inactive">>) -> <<"none">>;
mode2senders(<<"sendrecv">>) -> <<"both">>.

%% ===================================================================
%% From Jingle SDP to SDP    
%% ===================================================================

from_sdp(#sdp{} = Sdp, Creator) ->
    Jingle = #xmlel{
        name = <<"jingle">>,
        attrs = [
            {<<"xmlns">>, ?NS_JINGLE}
        ],
        children = []
    },
    Jingle1 = lists:foldl(
        fun(Attribute, Acc) ->
            from_sdp_attribute(Attribute, Acc, Sdp)
        end, Jingle, Sdp#sdp.attributes),
    lists:foldl(
        fun(Media, Acc) ->
            from_sdp_media(Media, Acc, Sdp, Creator)
        end, Jingle1, Sdp#sdp.medias).

% Convert sdp attributes

from_sdp_attribute({<<"group">>, [Semantics | Types]}, #xmlel{name = <<"jingle">>} = Jingle, _Sdp) ->
    Group = #xmlel{
        name = <<"group">>,
        attrs = [
            {<<"xmlns">>, <<"urn:xmpp:jingle:apps:grouping:0">>},
            {<<"semantics">>, Semantics},
            {<<"type">>, Semantics}
        ]
    },
    Group1 = lists:foldl(
        fun(Type, Acc) ->
            Content = #xmlel{
                name = <<"content">>,
                attrs = [
                    {<<"name">>, Type}
                ]
            },
            xml:append_subtags(Acc, [Content])
        end, Group, Types),
    xml:append_subtags(Jingle, [Group1]);

from_sdp_attribute(_, #xmlel{name = <<"jingle">>} = Jingle, _) -> Jingle.

% Convert sdp_m record

from_sdp_media(#sdp_m{} = SdpM, #xmlel{name = <<"jingle">>} = Jingle, _Sdp, Creator) ->
    Content = #xmlel{
        name = <<"content">>,
        attrs = [
            {<<"name">>, SdpM#sdp_m.media},
            {<<"creator">>, Creator}
        ],
        children = []
    },
    Content1 = lists:foldl(
        fun(Attribute, Acc) ->
            from_sdp_media_attribute(Attribute, Acc, SdpM)
        end, Content, SdpM#sdp_m.attributes),
    xml:append_subtags(Jingle, [Content1]).

% Convert "rtpmap" attribute

from_sdp_media_attribute({<<"rtpmap">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    {Content1, Description} = find_or_create_jingle_description(Content, SdpM),
    replace_tag_child(Description, from_sdp_media_attribute(Attr, Description, SdpM), Content1);

from_sdp_media_attribute({<<"rtpmap">>, [Id, Value]}, #xmlel{name = <<"description">>} = Description, _SdpM) -> 
    [Name, Clockrate | Channels] = binary:split(Value, <<"/">>, [global]),
    Payload = #xmlel{
        name = <<"payload-type">>,
        attrs = [
            {<<"id">>, Id},
            {<<"name">>, Name},
            {<<"clockrate">>, Clockrate},
            {<<"channels">>, 
                if 
                    Channels =/= [] -> 
                        [Channel] = Channels,
                        Channel;
                    true -> <<"1">>
                end
            }
        ]
    },
    xml:append_subtags(Description, [Payload]);

% Convert "fmtp" attribute

from_sdp_media_attribute({<<"fmtp">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    Content#xmlel{
        children = [from_sdp_media_attribute(Attr, El, SdpM) || El <- Content#xmlel.children]
    };

from_sdp_media_attribute({<<"fmtp">>, _} = Attr, #xmlel{name = <<"description">>} = Description, SdpM) -> 
    Description#xmlel{
        children = [from_sdp_media_attribute(Attr, El, SdpM) || El <- Description#xmlel.children]
    };

from_sdp_media_attribute({<<"fmtp">>, [Id, Value]}, #xmlel{name = <<"payload-type">>} = Payload, _SdpM) -> 
    PayloadId = xml:get_tag_attr_s(<<"id">>, Payload),
    if 
        Id =:= PayloadId ->
            Parameter = #xmlel{
                name = <<"parameter">>,
                attrs = [
                    {<<"name">>, <<"">>},
                    {<<"value">>, Value}
                ]
            },
            xml:append_subtags(Payload, [Parameter]);
        true ->
            Payload
    end;

% Convert "rtcp-fb" attribute

from_sdp_media_attribute({<<"rtcp-fb">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    {Content1, Description} = find_or_create_jingle_description(Content, SdpM),
    replace_tag_child(Description, from_sdp_media_attribute(Attr, Description, SdpM), Content1);

from_sdp_media_attribute({<<"rtcp-fb">>, [_, Type, Subtype]}, #xmlel{name = <<"description">>} = Description, _SdpM) -> 
    RtcpFb = #xmlel{
        name = <<"rtcp-fb">>,
        attrs = [
            {<<"xmlns">>, <<"urn:xmpp:jingle:apps:rtp:rtcp-fb:0">>},
            {<<"type">>, Type},
            {<<"subtype">>, Subtype}
        ]
    },
    xml:append_subtags(Description, [RtcpFb]);

% Convert "ice-ufrag" attribute

from_sdp_media_attribute({<<"ice-ufrag">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    {Content1, Transport} = find_or_create_jingle_transport(Content, SdpM),
    replace_tag_child(Transport, from_sdp_media_attribute(Attr, Transport, SdpM), Content1);

from_sdp_media_attribute({<<"ice-ufrag">>, [Value]}, #xmlel{name = <<"transport">>} = Transport, _SdpM) -> 
    xml:append_attrs(Transport, [{<<"ufrag">>, Value}]);

% Convert "ice-pwd" attribute

from_sdp_media_attribute({<<"ice-pwd">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    {Content1, Transport} = find_or_create_jingle_transport(Content, SdpM),
    replace_tag_child(Transport, from_sdp_media_attribute(Attr, Transport, SdpM), Content1);

from_sdp_media_attribute({<<"ice-pwd">>, [Value]}, #xmlel{name = <<"transport">>} = Transport, _SdpM) -> 
    xml:append_attrs(Transport, [{<<"pwd">>, Value}]);

% Convert "crypto" attribute

from_sdp_media_attribute({<<"crypto">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    Description = xml:get_subtag(Content, <<"description">>),
    replace_tag_child(Description, from_sdp_media_attribute(Attr, Description, SdpM), Content);

from_sdp_media_attribute({<<"crypto">>, _} = Attr, #xmlel{name = <<"description">>} = Description, SdpM) ->
    {Description1, Encryption} = find_or_create_jingle_encryption(Description, SdpM),
    replace_tag_child(Encryption, from_sdp_media_attribute(Attr, Encryption, SdpM), Description1);

from_sdp_media_attribute({<<"crypto">>, [Tag, CryptoSuite, KeyParams]}, #xmlel{name = <<"encryption">>} = Encryption, _SdpM) ->
    xml:append_subtags(Encryption, #xmlel{
        name = <<"crypto">>,
        attrs = [
            {<<"tag">>, Tag},
            {<<"crypto-suite">>, CryptoSuite},
            {<<"key-params">>, KeyParams}
        ]
    });

% Convert "candidate" attribute

from_sdp_media_attribute({<<"candidate">>, _} = Attr, #xmlel{name = <<"content">>} = Content, SdpM) ->
    {Content1, Transport} = find_or_create_jingle_transport(Content, SdpM),
    replace_tag_child(Transport, from_sdp_media_attribute(Attr, Transport, SdpM), Content1);

from_sdp_media_attribute({<<"candidate">>, [Foundation, Component, Protocol, Priority, Ip, Port, _Typ, Type]}, 
        #xmlel{name = <<"transport">>} = Transport, _SdpM) ->
    Candidate = #xmlel{
        name = <<"candidate">>,
        attrs = [
            {<<"foundation">>, Foundation},
            {<<"component">>, Component},
            {<<"protocol">>, Protocol},
            {<<"priority">>, Priority},
            {<<"ip">>, Ip},
            {<<"port">>, Port},
            {<<"type">>, Type},
            {<<"network">>, <<"1">>},
            {<<"id">>, base64:encode(crypto:strong_rand_bytes(36))}
        ]
    },
    xml:append_subtags(Transport, [Candidate]);

from_sdp_media_attribute({Mode, _} = _Attr, #xmlel{name = <<"content">>} = Content, _SdpM)
    when Mode =:= <<"sendrecv">> orelse Mode =:= <<"inactive">> orelse Mode =:= <<"recvonly">>
        orelse Mode =:= <<"sendonly">> ->
    xml:append_attrs(Content, [{<<"senders">>, mode2senders(Mode)}]);

% Convert other sdp_m attributes

from_sdp_media_attribute(_Attr, El, _SdpM) -> El.

% Helpers

find_or_create_jingle_description(#xmlel{name = <<"content">>} = Content, SdpM) ->
    case xml:get_subtag(Content, <<"description">>) of
        false -> 
            Description = #xmlel{
                name = <<"description">>,
                attrs = [
                    {<<"xmlns">>, <<"urn:xmpp:jingle:apps:rtp:1">>},
                    {<<"media">>, SdpM#sdp_m.media}
                ]
            },
            {xml:append_subtags(Content, [Description]), Description};
        Description -> 
            {Content, Description}
    end.

find_or_create_jingle_transport(#xmlel{name = <<"content">>} = Content, _SdpM) ->
    case xml:get_subtag(Content, <<"transport">>) of
        false -> 
            Transport = #xmlel{
                name = <<"transport">>,
                attrs = [
                    {<<"xmlns">>, <<"urn:xmpp:jingle:transports:ice-udp:1">>}
                ]
            },
            {xml:append_subtags(Content, [Transport]), Transport};
        Transport -> 
            {Content, Transport}
    end.

find_or_create_jingle_encryption(#xmlel{name = <<"description">>} = Description, _SdpM) ->
    case xml:get_subtag(Description, <<"encryption">>) of
        false -> 
            Encryption = #xmlel{
                name = <<"encryption">>,
                attrs = [
                    {<<"required">>, <<"1">>}
                ]
            },
            {xml:append_subtags(Description, [Encryption]), Encryption};
        Encryption -> 
            {Description, Encryption}
    end.

% Utils

replace_tag_child(Old, New, #xmlel{children = Children} = El) ->
    El#xmlel{children = replace_list_element(Old, New, Children)}.

replace_list_element(Old, New, List) when Old =:= New -> List;

replace_list_element(_Old, New, [_Old | Tail]) -> [New | Tail];

replace_list_element(Old, New, [Head | Tail]) ->
    [Head | replace_list_element(Old, New, Tail)];

replace_list_element(_, _, []) -> [].


%% ===================================================================
%% EUnit tests
%% ===================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("exml/include/exml.hrl").

sdp1_test() -> 
    JingleSdp = 
        <<
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='undefined' sid='1xjr68u3qzci'>",
                "<group xmlns='urn:xmpp:jingle:apps:grouping:0' type='BUNDLE' semantics='BUNDLE'>",
                    "<content name='audio'/>",
                    "<content name='video'/>",
                "</group>",
                "<group xmlns='urn:ietf:rfc:5888' type='BUNDLE'>",
                    "<content name='audio'/>",
                    "<content name='video'/>",
                "</group>",
                    "<content creator='initiator' name='audio' senders='both'>",
                        "<bundle xmlns='http://estos.de/ns/bundle'/>",
                        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio' ssrc='3915040383'>",
                            "<payload-type id='111' name='opus' clockrate='48000' channels='2'>",
                                "<parameter name='minptime' value='10'/>",
                            "</payload-type>",
                            "<payload-type id='103' name='ISAC' clockrate='16000' channels='1'/>",
                            "<payload-type id='104' name='ISAC' clockrate='32000' channels='1'/>",
                            "<payload-type id='0' name='PCMU' clockrate='8000' channels='1'/>",
                            "<payload-type id='8' name='PCMA' clockrate='8000' channels='1'/>",
                            "<payload-type id='106' name='CN' clockrate='32000' channels='1'/>",
                            "<payload-type id='105' name='CN' clockrate='16000' channels='1'/>",
                            "<payload-type id='13' name='CN' clockrate='8000' channels='1'/>",
                            "<payload-type id='126' name='telephone-event' clockrate='8000' channels='1'/>",
                            "<encryption required='1'>",
                                "<crypto tag='1' crypto-suite='AES_CM_128_HMAC_SHA1_80' key-params='inline:P/p3GbsCQwCKklwjqerO82pG51CUvM5pUaf64CnH'/>",
                            "</encryption>",
                            "<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='3915040383'>",
                                "<parameter name='cname' value='euv+fMnhT0bW9V4/'/>",
                                "<parameter name='msid' value='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne e786c139-403e-4341-8ca7-5455a2aa576e'/>",
                                "<parameter name='mslabel' value='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne'/>",
                                "<parameter name='label' value='e786c139-403e-4341-8ca7-5455a2aa576e'/>",
                            "</source>",
                            "<ssrc xmlns='http://estos.de/ns/ssrc' cname='euv+fMnhT0bW9V4/' msid='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne e786c139-403e-4341-8ca7-5455a2aa576e' mslabel='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne' label='e786c139-403e-4341-8ca7-5455a2aa576e' ssrc='3915040383'/>",
                            "<rtcp-mux/>",
                            "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='urn:ietf:params:rtp-hdrext:ssrc-audio-level' id='1'/>",
                        "</description>",
                        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='iUW8UZRHsWHh+JbA' pwd='786pFbv3bUtBhp4ewqi5Fc/s'>",
                            "<fingerprint xmlns='urn:xmpp:tmp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>61:DB:23:E2:40:87:4F:B9:DB:9D:53:87:AC:6A:15:4D:A9:2B:1D:8D:06:64:C1:C2:E8:6B:33:40:14:14:33:F8</fingerprint>",
                            "<candidate foundation='3290261477' component='1' protocol='udp' priority='2113937151' ip='10.10.18.38' port='39050' type='host' generation='0' network='1' id='hfghb58tie'/>",
                            "<candidate foundation='3290261477' component='2' protocol='udp' priority='2113937151' ip='10.10.18.38' port='39050' type='host' generation='0' network='1' id='hk6ci4qx51'/>",
                            "<candidate foundation='2325650197' component='1' protocol='tcp' priority='1509957375' ip='10.10.18.38' port='0' type='host' generation='0' network='1' id='f41geuzkt2'/>",
                            "<candidate foundation='2325650197' component='2' protocol='tcp' priority='1509957375' ip='10.10.18.38' port='0' type='host' generation='0' network='1' id='hrwmk304c1'/>",
                        "</transport>",
                    "</content>",
                    "<content creator='initiator' name='video' senders='both'>",
                        "<bundle xmlns='http://estos.de/ns/bundle'/>",
                        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video' ssrc='1861710339'>",
                            "<payload-type id='100' name='VP8' clockrate='90000' channels='1'>",
                                "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='ccm' subtype='fir'/>",
                                "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='nack'/>",
                                "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='goog-remb'/>",
                            "</payload-type>",
                            "<payload-type id='116' name='red' clockrate='90000' channels='1'/>",
                            "<payload-type id='117' name='ulpfec' clockrate='90000' channels='1'/>",
                            "<encryption required='1'>",
                                "<crypto tag='1' crypto-suite='AES_CM_128_HMAC_SHA1_80' key-params='inline:P/p3GbsCQwCKklwjqerO82pG51CUvM5pUaf64CnH'/>",
                            "</encryption>",
                            "<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='1861710339'>",
                                "<parameter name='cname' value='euv+fMnhT0bW9V4/'/>",
                                "<parameter name='msid' value='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne 21231a5c-e0b0-4ca6-be97-b8c974fa09ff'/>",
                                "<parameter name='mslabel' value='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne'/>",
                                "<parameter name='label' value='21231a5c-e0b0-4ca6-be97-b8c974fa09ff'/>",
                            "</source>",
                            "<ssrc xmlns='http://estos.de/ns/ssrc' cname='euv+fMnhT0bW9V4/' msid='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne 21231a5c-e0b0-4ca6-be97-b8c974fa09ff' mslabel='jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne' label='21231a5c-e0b0-4ca6-be97-b8c974fa09ff' ssrc='1861710339'/>",
                            "<rtcp-mux/>",
                            "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='urn:ietf:params:rtp-hdrext:toffset' id='2'/>",
                            "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time' id='3'/>",
                        "</description>",
                        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='iUW8UZRHsWHh+JbA' pwd='786pFbv3bUtBhp4ewqi5Fc/s'>",
                            "<fingerprint xmlns='urn:xmpp:tmp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>61:DB:23:E2:40:87:4F:B9:DB:9D:53:87:AC:6A:15:4D:A9:2B:1D:8D:06:64:C1:C2:E8:6B:33:40:14:14:33:F8</fingerprint>",
                            "<candidate foundation='3290261477' component='1' protocol='udp' priority='2113937151' ip='10.10.18.38' port='39050' type='host' generation='0' network='1' id='a65n0sz4yd'/>",
                            "<candidate foundation='3290261477' component='2' protocol='udp' priority='2113937151' ip='10.10.18.38' port='39050' type='host' generation='0' network='1' id='m4414u041m'/>",
                            "<candidate foundation='2325650197' component='1' protocol='tcp' priority='1509957375' ip='10.10.18.38' port='0' type='host' generation='0' network='1' id='a8mc7myqbn'/>",
                            "<candidate foundation='2325650197' component='2' protocol='tcp' priority='1509957375' ip='10.10.18.38' port='0' type='host' generation='0' network='1' id='x35q36n8do'/>",
                    "</transport>",
                "</content>",
            "</jingle>"
        >>,
    Sdp = 
        <<
            "v=0\r\n",
            "o=- 1923518516 2 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "a=group:BUNDLE audio video\r\n",
            "m=audio 1 RTP/SAVPF 111 103 104 0 8 106 105 13 126\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=rtcp:1 IN IP4 0.0.0.0\r\n",
            "a=ice-ufrag:iUW8UZRHsWHh+JbA\r\n",
            "a=ice-pwd:786pFbv3bUtBhp4ewqi5Fc/s\r\n",
            "a=fingerprint:sha-256 61:DB:23:E2:40:87:4F:B9:DB:9D:53:87:AC:6A:15:4D:A9:2B:1D:8D:06:64:C1:C2:E8:6B:33:40:14:14:33:F8\r\n",
            "a=setup:actpass\r\n",
            "a=sendrecv\r\n",
            "a=mid:audio\r\n",
            "a=rtcp-mux\r\n",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:P/p3GbsCQwCKklwjqerO82pG51CUvM5pUaf64CnH\r\n",
            "a=rtpmap:111 opus/48000/2\r\n",
            "a=fmtp:111 minptime=10\r\n",
            "a=rtpmap:103 ISAC/16000\r\n",
            "a=rtpmap:104 ISAC/32000\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:106 CN/32000\r\n",
            "a=rtpmap:105 CN/16000\r\n",
            "a=rtpmap:13 CN/8000\r\n",
            "a=rtpmap:126 telephone-event/8000\r\n",
            "a=fmtp:126 cname=euv+fMnhT0bW9V4/;msid=jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne e786c139-403e-4341-8ca7-5455a2aa576e;mslabel=jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne;label=e786c139-403e-4341-8ca7-5455a2aa576e\r\n",
            "a=candidate:3290261477 1 udp 2113937151 10.10.18.38 39050 typ host generation 0\r\n",
            "a=candidate:3290261477 2 udp 2113937151 10.10.18.38 39050 typ host generation 0\r\n",
            "a=candidate:2325650197 1 tcp 1509957375 10.10.18.38 0 typ host generation 0\r\n",
            "a=candidate:2325650197 2 tcp 1509957375 10.10.18.38 0 typ host generation 0\r\n",
            "m=video 1 RTP/SAVPF 100 116 117\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=rtcp:1 IN IP4 0.0.0.0\r\n",
            "a=ice-ufrag:iUW8UZRHsWHh+JbA\r\n",
            "a=ice-pwd:786pFbv3bUtBhp4ewqi5Fc/s\r\n",
            "a=fingerprint:sha-256 61:DB:23:E2:40:87:4F:B9:DB:9D:53:87:AC:6A:15:4D:A9:2B:1D:8D:06:64:C1:C2:E8:6B:33:40:14:14:33:F8\r\n",
            "a=setup:actpass\r\n",
            "a=sendrecv\r\n",
            "a=mid:video\r\n",
            "a=rtcp-mux\r\n",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:P/p3GbsCQwCKklwjqerO82pG51CUvM5pUaf64CnH\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "a=rtcp-fb:100 ccm fir\r\n",
            "a=rtpmap:116 red/90000\r\n",
            "a=rtpmap:117 ulpfec/90000\r\n",
            "a=fmtp:117 cname=euv+fMnhT0bW9V4/;msid=jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne 21231a5c-e0b0-4ca6-be97-b8c974fa09ff;mslabel=jy1RjckgN7VZmY3rEQhEjVNe1tTmSaFDnOne;label=21231a5c-e0b0-4ca6-be97-b8c974fa09ff\r\n",
            "a=candidate:3290261477 1 udp 2113937151 10.10.18.38 39050 typ host generation 0\r\n",
            "a=candidate:3290261477 2 udp 2113937151 10.10.18.38 39050 typ host generation 0\r\n",
            "a=candidate:2325650197 1 tcp 1509957375 10.10.18.38 0 typ host generation 0\r\n",
            "a=candidate:2325650197 2 tcp 1509957375 10.10.18.38 0 typ host generation 0\r\n"
        >>,
    {ok, Xml} = exml:parse(JingleSdp),
    Result = nksip_sdp:unparse(to_sdp(Xml)),
    ?debugFmt("~n~s", [Result]),
    ?assertMatch(Sdp, Result).

sdp2_test() ->
    Sdp = 
        <<
            "v=0\r\n",
            "o=root 700453084 700453084 IN IP4 10.10.18.38\r\n",
            "s=Asterisk PBX 12.1.0\r\n",
            "c=IN IP4 10.10.18.38\r\n",
            "t=0 0\r\n",
            "m=audio 16802 RTP/AVPF 3 0 8 101\r\n",
            "a=rtpmap:3 GSM/8000\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=fmtp:101 0-16\r\n",
            "a=silenceSupp:off - - - -\r\n",
            "a=ptime:20\r\n",
            "a=maxptime:150\r\n",
            "a=ice-ufrag:682902eb723563cc0eb95a874bc8759c\r\n",
            "a=ice-pwd:097211bc6530e2e9733e00d01c8af6a6\r\n",
            "a=candidate:Ha0a1226 1 UDP 2130706431 10.10.18.38 16802 typ host\r\n",
            "a=candidate:S5bdb0f7e 1 UDP 1694498815 91.219.15.126 16802 typ srflx\r\n",
            "a=candidate:Ha0a1226 2 UDP 2130706430 10.10.18.38 16803 typ host\r\n",
            "a=candidate:S5bdb0f7e 2 UDP 1694498814 91.219.15.126 16804 typ srflx\r\n",
            "a=sendrecv\r\n"
        >>,
    JingleSdp = 
        <<
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-accept' initiator='romeo@mongoose.adruz.spb.unison.com' responder='juliet@asterisk.adruz.spb.unison.com' sid='12345678'>",
                "<content creator='responder' name='audio' senders='both'>",
                    "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>",
                        "<payload-type id='3' name='GSM' clockrate='8000' channels='1'/>",
                        "<payload-type id='0' name='PCMU' clockrate='8000' channels='1'/>",
                        "<payload-type id='8' name='PCMA' clockrate='8000' channels='1'/>",
                        "<payload-type id='101' name='telephone-event' clockrate='8000' channels='1'>",
                            "<parameter name='' value='0-16'/>",
                        "</payload-type>",
                    "</description>",
                    "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='682902eb723563cc0eb95a874bc8759c' pwd='097211bc6530e2e9733e00d01c8af6a6'>",
                        "<candidate foundation='Ha0a1226' component='1' protocol='udp' priority='2130706431' ip='10.10.18.38' port='16802' type='host' network='1' id='bhkd9mzksw'/>",
                        "<candidate foundation='S5bdb0f7e' component='1' protocol='udp' priority='1694498815' ip='91.219.15.126' port='16802' type='srflx' network='1' id='m5uvipu8yy'/>",
                        "<candidate foundation='Ha0a1226' component='2' protocol='udp' priority='2130706430' ip='10.10.18.38' port='16803' type='host' network='1' id='8z7zjdpr9q'/>",
                        "<candidate foundation='S5bdb0f7e' component='2' protocol='udp' priority='1694498814' ip='91.219.15.126' port='16804' type='srflx' network='1' id='kkv04miym7'/>",
                    "</transport>",
                "</content>",
                "<content creator='responder' name='audio' senders='both'>",
                    "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>",
                        "<payload-type id='3' name='GSM' clockrate='8000' channels='1'/>",
                        "<payload-type id='0' name='PCMU' clockrate='8000' channels='1'/>",
                        "<payload-type id='8' name='PCMA' clockrate='8000' channels='1'/>",
                        "<payload-type id='101' name='telephone-event' clockrate='8000' channels='1'>",
                            "<parameter name='' value='0-16'/>",
                        "</payload-type>",
                    "</description>",
                    "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='682902eb723563cc0eb95a874bc8759c' pwd='097211bc6530e2e9733e00d01c8af6a6'>",
                        "<candidate foundation='Ha0a1226' component='1' protocol='udp' priority='2130706431' ip='10.10.18.38' port='16802' type='host' network='1' id='v9veji78xe'/>",
                        "<candidate foundation='S5bdb0f7e' component='1' protocol='udp' priority='1694498815' ip='91.219.15.126' port='16802' type='srflx' network='1' id='unbczkdfgh'/>",
                        "<candidate foundation='Ha0a1226' component='2' protocol='udp' priority='2130706430' ip='10.10.18.38' port='16803' type='host' network='1' id='7ptprh10hn'/>",
                        "<candidate foundation='S5bdb0f7e' component='2' protocol='udp' priority='1694498814' ip='91.219.15.126' port='16804' type='srflx' network='1' id='y1o1yc1mv2'/>",
                    "</transport>",
                "</content>",
            "</jingle>"
        >>,
    Result = exml:to_binary(from_sdp(nksip_sdp:parse(Sdp), <<"responder">>)),
    ?debugFmt("~n~s", [Result]),
    ?assertMatch(JingleSdp, Result).

-endif.
