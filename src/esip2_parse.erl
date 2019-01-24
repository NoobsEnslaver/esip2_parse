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
Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7\r
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
        {ok, Method, Msg1} ->
            case parse_ruri(Msg1) of
                {ok, RURI, Msg2} ->
                    case parse_sip_protocol_version(Msg2) of
                        {ok, Version, Msg3} ->
                            {ok, #request_line{method = Method, ruri = RURI, version = Version}, Msg3};
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

parse_status_line(Msg) ->
    case parse_sip_protocol_version(Msg) of
        {ok, Version, Msg1} ->
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

parse_ruri([$ | Msg]) ->
    parse_ruri(Msg);
parse_ruri(Msg) ->
    {RURI, Rest} = take_until($ , Msg),
    {ok, RURI, Rest}.

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




parse_resp_code([$  | Msg]) ->
    parse_resp_code(Msg);
parse_resp_code(Msg) ->
    {Code, Rest1} = take_until($ , Msg),
    try {ok, list_to_integer(Code), Rest1}
    catch _:_ -> {error, bad_resp_code, Code}
    end.

parse_resp_phrase([$  | Rest]) ->
    parse_resp_phrase(Rest);
parse_resp_phrase(Msg) ->
    parse_resp_phrase(Msg, "").
parse_resp_phrase([$\r, $\n | Rest], Acc) ->
    {ok, lists:reverse(Acc), Rest};
parse_resp_phrase([A | Rest], Acc) ->
    parse_resp_phrase(Rest, [A | Acc]).

parse_method([$  | Msg]) ->
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


parse_sip_protocol_version([$  | Rest]) ->
    parse_sip_protocol_version(Rest);
parse_sip_protocol_version([$S,$I,$P, $/, A, $., B,$\r,$\n | Rest]) ->
    try {ok, list_to_float([A,$.,B]), Rest}
    catch _:E -> {error, bad_sip_protocol_version, E}
    end;
parse_sip_protocol_version([$S,$I,$P, $/, A, $., B | Rest]) ->
    try {ok, list_to_float([A,$.,B]), Rest}
    catch _:E -> {error, bad_sip_protocol_version, E}
    end.

%% --------- headers ------------------
parse_hd_via([$\r,$\n | Rest]) ->
    {ok, #hd_via{}, Rest};
parse_hd_via([_ | Msg]) ->
    parse_hd_via(Msg).

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

%% --------- utils --------------------
take_until(X, Msg) ->
    take_until(X, Msg, "").
take_until(_, [], Acc) ->
    lists:reverse(Acc);
take_until(X, [X | Rest], Acc) ->
    {lists:reverse(Acc), Rest};
take_until(X, [A | Rest], Acc) ->
    take_until(X, Rest, [A | Acc]).
