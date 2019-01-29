-module(esip2_parse).

-compile([export_all]).
-include("esip2_parse.hrl").
-include("esip2_parse_utils.hrl").

-define(COLLECT(X, Acc), case X of
                        {ok, Result, Rest} ->
                                 (?FUNCTION_NAME)(Rest, [Result | Acc]);
                             Error -> Error
                         end).

test_req_msg() ->
    "REGISTER sips:ss2.biloxi.example.com SIP/2.0\r
Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7;maddr=qwe1;ttl=201;lol=kek;lr\r
Max-Forwards: 70\r
From: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl\r
To: Bob <sips:bob@biloxi.example.com>\r
Call-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com\r
CSeq: 1 REGISTER\r
Contact: <sips:bob@client.biloxi.example.com>\r
Content-Length: 0\r
\r
[BODY]".

test_resp_msg() ->
    "SIP/2.0 401 Unauthorized\r
Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7
 ;received=192.0.2.201\r
From: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl\r
To: Bob <sips:bob@biloxi.example.com>;tag=1410948204\r
Call-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com\r
CSeq: 1 REGISTER\r
WWW-Authenticate: Digest realm=\"atlanta.example.com\", qop=\"auth\",
 nonce=\"ea9c8e88df84f1cec4341ae6cbe5a359\",
 opaque=\"\", stale=FALSE, algorithm=MD5\r
Content-Length: 0\r
\r
[BODY]".

test_req() ->
    parse_req(test_req_msg()).

test_resp() ->
    parse_resp(test_resp_msg()).

%% ---------- parsers ----------------

parse(["SIP/" ++ _Rest] = Msg) ->
    parse_resp(Msg);
parse(Msg) ->
    parse_req(Msg).

parse_req(Msg) ->
    case parse_request_line(Msg) of
        {ok, #request_line{method = Method, ruri = RURI, version = Version}, Msg1} ->
            case parse_headers(Msg1) of
                {ok, Headers, Msg2} ->
                    #sip_req{body = parse_body(Msg2),
                             headers = Headers,
                             ruri = RURI,
                             method = Method,
                             version = Version};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

parse_resp(Msg) ->
    case parse_status_line(Msg) of
        {ok, #status_line{code = Code, phrase = Phrase, version = Version}, Msg1} ->
            case parse_headers(Msg1) of
                {ok, Headers, Msg2} ->
                    #sip_resp{body = parse_body(Msg2),
                              headers = Headers,
                              version = Version,
                              code = Code,
                              phrase = Phrase};
                Error -> Error
            end;
        Error -> Error
    end.

parse_request_line(Msg) ->
    case parse_method(Msg) of
        {ok, Method, [?SP | Msg1]} ->
            case parse_sip_uri(Msg1) of
                {ok, RURI, [?SP | Msg2]} ->
                    case parse_sip_protocol_version(Msg2) of
                        {ok, Version, [$\r,$\n | Msg3]} ->
                            {ok, #request_line{method = Method, ruri = RURI, version = Version}, Msg3};
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

parse_status_line(Msg) ->
    case parse_sip_protocol_version(Msg) of
        {ok, Version, [?SP | Msg1]} ->
            case parse_resp_code(Msg1) of
                {ok, Code, Msg2} ->
                    case parse_resp_phrase(Msg2) of
                        {ok, Phrase, Msg3} ->
                            {ok, #status_line{code = Code, phrase = Phrase, version = Version}, Msg3};
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

parse_body(Msg) ->
    Msg.

%% ---------------------------- headers parsers ------------------------------------
parse_headers(Msg) ->
    parse_headers(Msg, []).

%% general case to stop on body
parse_headers([$\r,$\n | Rest], Acc) ->
    {ok, lists:reverse(Acc), Rest};

%% hd_via
parse_headers("Via: " ++ Msg, Acc) -> ?COLLECT(parse_hd_via(Msg), Acc);
parse_headers("VIA: " ++ Msg, Acc) -> ?COLLECT(parse_hd_via(Msg), Acc);
parse_headers("via: " ++ Msg, Acc) -> ?COLLECT(parse_hd_via(Msg), Acc);
%% hd_to
parse_headers("to: " ++ Msg, Acc) -> ?COLLECT(parse_hd_to(Msg), Acc);
parse_headers("To: " ++ Msg, Acc) -> ?COLLECT(parse_hd_to(Msg), Acc);
parse_headers("TO: " ++ Msg, Acc) -> ?COLLECT(parse_hd_to(Msg), Acc);
%% hd_from
parse_headers("From: " ++ Msg, Acc) -> ?COLLECT(parse_hd_from(Msg), Acc);
parse_headers("FROM: " ++ Msg, Acc) -> ?COLLECT(parse_hd_from(Msg), Acc);
parse_headers("from: " ++ Msg, Acc) -> ?COLLECT(parse_hd_from(Msg), Acc);
%% hd_call_id
parse_headers("call-id: " ++ Msg, Acc) -> ?COLLECT(parse_hd_call_id(Msg), Acc);
parse_headers("Call-Id: " ++ Msg, Acc) -> ?COLLECT(parse_hd_call_id(Msg), Acc);
parse_headers("Call-ID: " ++ Msg, Acc) -> ?COLLECT(parse_hd_call_id(Msg), Acc);
parse_headers("CALL-ID: " ++ Msg, Acc) -> ?COLLECT(parse_hd_call_id(Msg), Acc);
%% hd_cseq
parse_headers("cseq: " ++ Msg, Acc) -> ?COLLECT(parse_hd_cseq(Msg), Acc);
parse_headers("Cseq: " ++ Msg, Acc) -> ?COLLECT(parse_hd_cseq(Msg), Acc);
parse_headers("CSeq: " ++ Msg, Acc) -> ?COLLECT(parse_hd_cseq(Msg), Acc);
parse_headers("CSEQ: " ++ Msg, Acc) -> ?COLLECT(parse_hd_cseq(Msg), Acc);
%% hd_www_authenticate
parse_headers("WWW-Authenticate: " ++ Msg, Acc) -> ?COLLECT(parse_hd_www_authenticate(Msg), Acc);
parse_headers("Www-Authenticate: " ++ Msg, Acc) -> ?COLLECT(parse_hd_www_authenticate(Msg), Acc);
parse_headers("www-authenticate: " ++ Msg, Acc) -> ?COLLECT(parse_hd_www_authenticate(Msg), Acc);
parse_headers("WWW-AUTHENTICATE: " ++ Msg, Acc) -> ?COLLECT(parse_hd_www_authenticate(Msg), Acc);
%% hd_max_forwards
parse_headers("Max-Forwards: " ++ Msg, Acc) -> ?COLLECT(parse_hd_max_forwards(Msg), Acc);
parse_headers("MAX-FORWARDS: " ++ Msg, Acc) -> ?COLLECT(parse_hd_max_forwards(Msg), Acc);
parse_headers("max-forwards: " ++ Msg, Acc) -> ?COLLECT(parse_hd_max_forwards(Msg), Acc);
%% hd_contact
parse_headers("Contact: " ++ Msg, Acc) -> ?COLLECT(parse_hd_contact(Msg), Acc);
parse_headers("CONTACT: " ++ Msg, Acc) -> ?COLLECT(parse_hd_contact(Msg), Acc);
parse_headers("contact: " ++ Msg, Acc) -> ?COLLECT(parse_hd_contact(Msg), Acc);
%% hd_content_length
parse_headers("Content-Length: " ++ Msg, Acc) -> ?COLLECT(parse_hd_content_length(Msg), Acc);
parse_headers("CONTENT-LENGTH: " ++ Msg, Acc) -> ?COLLECT(parse_hd_content_length(Msg), Acc);
parse_headers("content-length: " ++ Msg, Acc) -> ?COLLECT(parse_hd_content_length(Msg), Acc).


parse_resp_code([C,O,D,?SP | Rest]) ->
    try {ok, list_to_integer([C,O,D]), Rest}
    catch _:_ -> {error, bad_resp_code, [C,O,D]}
    end.

parse_resp_phrase([?SP | Rest]) ->
    parse_resp_phrase(Rest);
parse_resp_phrase(Msg) ->
    parse_resp_phrase(Msg, "").
parse_resp_phrase([$\r, $\n | Rest], Acc) ->
    {ok, lists:reverse(Acc), Rest};
parse_resp_phrase([A | Rest], Acc) ->
    parse_resp_phrase(Rest, [A | Acc]).

parse_method([?SP | Msg]) ->
    parse_method(Msg);
parse_method("INVITE" ++ Rest) ->
    {ok, invite, Rest};
parse_method("ACK" ++ Rest) ->
    {ok, ack, Rest};
parse_method("MESSAGE" ++ Rest) ->
    {ok, message, Rest};
parse_method("BYE" ++ Rest) ->
    {ok, bye, Rest};
parse_method("CANCEL" ++ Rest) ->
    {ok, cancel, Rest};
parse_method("REGISTER" ++ Rest) ->
    {ok, register, Rest};
parse_method("OPTIONS " ++ Rest) ->
    {ok, options, Rest};
parse_method("SUBSCRIBE" ++ Rest) ->
    {ok, subscribe, Rest};
parse_method("NOTIFY" ++ Rest) ->
    {ok, notify, Rest};
parse_method("UPDATE" ++ Rest) ->
    {ok, update, Rest};
parse_method("PUBLISH" ++ Rest) ->
    {ok, publish, Rest};
parse_method("INFO" ++ Rest) ->
    {ok, info, Rest};
parse_method("PRACK" ++ Rest) ->
    {ok, prack, Rest};
parse_method("REFER" ++ Rest) ->
    {ok, refer, Rest};
parse_method(Msg) ->
    {error, Msg}.

parse_sip_protocol_version("SIP/" ++ [A,$.,B | Rest]) ->
    try {ok, list_to_float([A,$.,B]), Rest}
    catch _:E -> {error, bad_sip_protocol_version, E}
    end.

parse_sip_uri("sip:" ++ UserInfo) ->
    parse_sip_uri(UserInfo, #addr{scheme = sip});
parse_sip_uri("sips:" ++ UserInfo) ->
    parse_sip_uri(UserInfo, #addr{scheme = sips}).

parse_sip_uri(UserInfo, Addr) ->
    {ok, {Host, Port}, Rest} = parse_host_port(UserInfo),
    {ok, Addr#addr{host = Host, port = Port}, Rest}.

parse_host(Msg) ->
    {Host, Rest} = string:take(Msg, ?HOST),
    {ok, Host, Rest}.

parse_host_port(Msg) ->
    case parse_host(Msg) of
        {ok, Host, [$: | Rest]} ->
            {Port, Rest1} = string:take(Rest, ?NUM),
            {ok, {Host, list_to_integer(Port)}, Rest1};
        {ok, Host, Rest} ->
            {ok, {Host, undefined}, Rest}
    end.

%% --------- headers ------------------
%% Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7
%%  ;received=192.0.2.201\r\n

parse_hd_via(Msg) ->
    case parse_sip_protocol_version(Msg) of
        {ok, Version, [$/ | Rest1]} ->
            case parse_transport(Rest1) of
                {ok, Transport, [?SP | Rest2]} ->
                    case parse_host_port(Rest2) of
                        {ok, {Host, Port}, Rest3} ->
                            ViaWithoutParams = #hd_via{protocol = sip   %TODO
                                                      ,version = Version
                                                      ,transport = Transport
                                                      ,sent_by_host = Host
                                                      ,sent_by_port = Port},
                            {Params, Rest4} = parse_params(Rest3),
                            {ok, parse_hd_via(Params, ViaWithoutParams), Rest4};
                        Error -> Error
                    end
            end;
        Error -> Error
    end.

parse_hd_via([], Via) ->
    Via;
parse_hd_via([{"branch", B} | Rest], Via) ->
    parse_hd_via(Rest, Via#hd_via{branch = B});
parse_hd_via([{"ttl", T} | Rest], Via) ->
    parse_hd_via(Rest, Via#hd_via{ttl = list_to_integer(T)});
parse_hd_via([{"maddr", M} | Rest], Via) ->
    parse_hd_via(Rest, Via#hd_via{maddr = M});
parse_hd_via([{"received", R} | Rest], Via) ->
    parse_hd_via(Rest, Via#hd_via{received = R});
parse_hd_via([Ext | Rest], Via) ->
    parse_hd_via(Rest, Via#hd_via{extension = [Ext | Via#hd_via.extension]}).

parse_hd_to([$\r,$\n | Rest]) ->
    {ok, #hd_to{}, Rest};
parse_hd_to([_ | Msg]) ->
    parse_hd_to(Msg).

parse_hd_from([$\r,$\n | Rest]) ->
    {ok, #hd_from{}, Rest};
parse_hd_from([_ | Msg]) ->
    parse_hd_from(Msg).

parse_hd_cseq([$\r,$\n | Rest]) ->
    {ok, #hd_cseq{}, Rest};
parse_hd_cseq([_ | Msg]) ->
    parse_hd_cseq(Msg).

parse_hd_www_authenticate([$\r,$\n | Rest]) ->
    {ok, #hd_www_authenticate{}, Rest};
parse_hd_www_authenticate([_ | Msg]) ->
    parse_hd_www_authenticate(Msg).

parse_hd_max_forwards([$\r,$\n | Rest]) ->
    {ok, #hd_max_forwards{}, Rest};
parse_hd_max_forwards([_ | Msg]) ->
    parse_hd_max_forwards(Msg).

parse_hd_call_id([$\r,$\n | Rest]) ->
    {ok, #hd_call_id{}, Rest};
parse_hd_call_id([_ | Msg]) ->
    parse_hd_call_id(Msg).

parse_hd_contact([$\r,$\n | Rest]) ->
    {ok, #hd_contact{}, Rest};
parse_hd_contact([_ | Msg]) ->
    parse_hd_contact(Msg).

parse_hd_content_length([$\r,$\n | Rest]) ->
    {ok, #hd_content_length{}, Rest};
parse_hd_content_length([_ | Msg]) ->
    parse_hd_content_length(Msg).


parse_params(Msg) ->
    {Acc, Rest} = parse_params(Msg, []),
    {lists:reverse(Acc), Rest}.

parse_params([?SP | Msg], Acc) ->
    parse_params(Msg, Acc);
parse_params([$\r,$\n | Rest], Acc) ->
    {Acc, Rest};
parse_params([$\n | Msg], Acc) ->
    parse_params(Msg, Acc);
parse_params([$; | Msg], Acc) ->
    case string:take(Msg, ?GENERIC_PARAM_DELIMS, true) of
        {Key, [$= | Rest]} ->
            io:format("take1: ~p~n", [Key]),
            {Value, Rest1} = string:take(Rest, ?GENERIC_PARAM_DELIMS, true),
            io:format("take2: ~p~n", [Value]),
            parse_params(Rest1, [{Key, Value} | Acc]);
        {Key, Rest} ->
            io:format("take3: ~p~n", [Key]),
            parse_params(Rest, [Key | Acc])
    end.

parse_transport(Msg) ->
    {T, Rest} = string:take(Msg, [?SP], true),
    case string:lowercase(T) of
        "tcp" -> {ok, tcp, Rest};
        "udp" -> {ok, udp, Rest};
        "tls" -> {ok, tls, Rest};
        "sctp"-> {ok, sctp, Rest};
        "ws"  -> {ok, ws, Rest};
        "wss" -> {ok, wss, Rest};
        Error -> {error, bad_transport, Error}
    end.


%% --------- utils --------------------

skip_ws([?SP | Rest]) ->
    skip_ws(Rest);
skip_ws([$\t | Rest]) ->
    skip_ws(Rest);
skip_ws(Msg) ->
    Msg.
