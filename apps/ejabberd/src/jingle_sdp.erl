-module(jingle_sdp).

%% ----------------------------------------------------------------------
%% Exports

-export([to_sdp/1]).

%% ----------------------------------------------------------------------
%% Imports

-include("jlib.hrl").

-include_lib("nksip/include/nksip.hrl").

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
    Mode =
        case Senders of
            <<"initiator">> -> <<"sendonly">>;
            <<"responder">> -> <<"recvonly">>;
            <<"none">> -> <<"inactive">>;
            <<"both">> -> <<"sendrecv">>
        end,
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
    Sdp#sdp{medias = Medias ++ [SdpM3]}.

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
    SdpM2 = 
        if 
            Fingerprint =/= false ->
                parse_content_transport_fingerprint(Fingerprint, SdpM1);
            true -> 
                SdpM1
        end,
    parse_content_transport_candidates(Transport, SdpM2).

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
        attributes = [
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
            ]} | Attrs
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

%% ===================================================================
%% EUnit tests
%% ===================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("exml/include/exml.hrl").

sdp1_test() -> 
    JingleSdp = 
        <<
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='undefined' sid='hhpn7tko321s'>",
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
                    "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio' ssrc='3566948691'>",
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
                            "<crypto tag='1' crypto-suite='AES_CM_128_HMAC_SHA1_80' key-params='inline:lbM0aFEaVUNQYfQ2IYI1PR2jpCWbn7J8FtfoPMjX'/>",
                        "</encryption>",
                        "<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='3566948691'>",
                            "<parameter name='cname' value='duClnLB8nsEG/c37'/>",
                            "<parameter name='msid' value='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 250d5632-b67a-4082-98b9-e1f1b85bbcbd'/>",
                            "<parameter name='mslabel' value='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf'/>",
                            "<parameter name='label' value='250d5632-b67a-4082-98b9-e1f1b85bbcbd'/>",
                        "</source>",
                        "<ssrc xmlns='http://estos.de/ns/ssrc' cname='duClnLB8nsEG/c37' msid='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 250d5632-b67a-4082-98b9-e1f1b85bbcbd' mslabel='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf' label='250d5632-b67a-4082-98b9-e1f1b85bbcbd' ssrc='3566948691'/>",
                        "<rtcp-mux/>",
                        "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='urn:ietf:params:rtp-hdrext:ssrc-audio-level' id='1'/>",
                    "</description>",
                    "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='fNX3arXP9sWiq7sJ' pwd='gttoUN1BNjF79EjK1Au9hEnz'>",
                        "<fingerprint xmlns='urn:xmpp:tmp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>",
                            "15:FF:FC:12:DD:A8:02:3F:D0:B0:2E:AB:07:46:B3:3B:CF:D6:83:BA:3F:3C:7E:5A:55:B7:A0:D0:98:C8:83:62",
                        "</fingerprint>",
                    "</transport>",
                "</content>",
                "<content creator='initiator' name='video' senders='both'>",
                    "<bundle xmlns='http://estos.de/ns/bundle'/>",
                    "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video' ssrc='334887616'>",
                        "<payload-type id='100' name='VP8' clockrate='90000' channels='1'>",
                            "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='ccm' subtype='fir'/>",
                            "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='nack'/>",
                            "<rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='goog-remb'/>",
                        "</payload-type>",
                        "<payload-type id='116' name='red' clockrate='90000' channels='1'/>",
                        "<payload-type id='117' name='ulpfec' clockrate='90000' channels='1'/>",
                        "<encryption required='1'>",
                            "<crypto tag='1' crypto-suite='AES_CM_128_HMAC_SHA1_80' key-params='inline:lbM0aFEaVUNQYfQ2IYI1PR2jpCWbn7J8FtfoPMjX'/>",
                        "</encryption>",
                        "<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='334887616'>",
                            "<parameter name='cname' value='duClnLB8nsEG/c37'/>",
                            "<parameter name='msid' value='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 0bd05dd3-d2b4-4d44-b840-bea09c726a27'/>",
                            "<parameter name='mslabel' value='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf'/>",
                            "<parameter name='label' value='0bd05dd3-d2b4-4d44-b840-bea09c726a27'/>",
                        "</source>",
                        "<ssrc xmlns='http://estos.de/ns/ssrc' cname='duClnLB8nsEG/c37' msid='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 0bd05dd3-d2b4-4d44-b840-bea09c726a27' mslabel='L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf' label='0bd05dd3-d2b4-4d44-b840-bea09c726a27' ssrc='334887616'/>",
                        "<rtcp-mux/>",
                        "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='urn:ietf:params:rtp-hdrext:toffset' id='2'/>",
                        "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' uri='http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time' id='3'/>",
                    "</description>",
                    "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='fNX3arXP9sWiq7sJ' pwd='gttoUN1BNjF79EjK1Au9hEnz'>",
                        "<fingerprint xmlns='urn:xmpp:tmp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>",
                            "15:FF:FC:12:DD:A8:02:3F:D0:B0:2E:AB:07:46:B3:3B:CF:D6:83:BA:3F:3C:7E:5A:55:B7:A0:D0:98:C8:83:62",
                            "</fingerprint>",
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
            "a=ice-ufrag:fNX3arXP9sWiq7sJ\r\n",
            "a=ice-pwd:gttoUN1BNjF79EjK1Au9hEnz\r\n",
            "a=fingerprint:sha-256 15:FF:FC:12:DD:A8:02:3F:D0:B0:2E:AB:07:46:B3:3B:CF:D6:83:BA:3F:3C:7E:5A:55:B7:A0:D0:98:C8:83:62\r\n",
            "a=setup:actpass\r\n",
            "a=sendrecv\r\n",
            "a=mid:audio\r\n",
            "a=rtcp-mux\r\n",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:lbM0aFEaVUNQYfQ2IYI1PR2jpCWbn7J8FtfoPMjX\r\n",
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
            "a=fmtp:126 cname=duClnLB8nsEG/c37;msid=L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 250d5632-b67a-4082-98b9-e1f1b85bbcbd;mslabel=L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf;label=250d5632-b67a-4082-98b9-e1f1b85bbcbd\r\n",
            "m=video 1 RTP/SAVPF 100 116 117\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=rtcp:1 IN IP4 0.0.0.0\r\n",
            "a=ice-ufrag:fNX3arXP9sWiq7sJ\r\n",
            "a=ice-pwd:gttoUN1BNjF79EjK1Au9hEnz\r\n",
            "a=fingerprint:sha-256 15:FF:FC:12:DD:A8:02:3F:D0:B0:2E:AB:07:46:B3:3B:CF:D6:83:BA:3F:3C:7E:5A:55:B7:A0:D0:98:C8:83:62\r\n",
            "a=setup:actpass\r\n",
            "a=sendrecv\r\n",
            "a=mid:video\r\n",
            "a=rtcp-mux\r\n",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:lbM0aFEaVUNQYfQ2IYI1PR2jpCWbn7J8FtfoPMjX\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "a=rtcp-fb:100 ccm fir\r\n",
            "a=rtpmap:116 red/90000\r\n",
            "a=rtpmap:117 ulpfec/90000\r\n",
            "a=fmtp:117 cname=duClnLB8nsEG/c37;msid=L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf 0bd05dd3-d2b4-4d44-b840-bea09c726a27;mslabel=L4zNw8L2I5GxorjeTiSEpNZTSdOkXhbe4Bjf;label=0bd05dd3-d2b4-4d44-b840-bea09c726a27\r\n"
        >>,
    {ok, Xml} = exml:parse(JingleSdp),
    Result = nksip_sdp:unparse(to_sdp(Xml)),
    ?debugFmt("~n~s", [Result]),
    ?assertMatch(Sdp, Result).

-endif.
