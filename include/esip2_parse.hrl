-ifndef(ESIP2_PARSE_HRL).
-define(ESIP2_PARSE_HRL, 1).

-type scheme() :: sip | sips | tel | mail | http | https.
-type generic_param() :: {string(), string()} | string().
-type code() :: 100..699.
-type sip_method() :: invite
                    | ack
                    | message
                    | bye
                    | cancel
                    | register
                    | options
                    | subscribe
                    | notify
                    | update
                    | publish
                    | info
                    | prack
                    | refer.

-type transport() :: udp | tcp | sctp | ws | wss | tls.
-type digest_algorithm() ::'ripemd160WithRSA'
                         | 'ssl2-md5'
                         | 'sha384'
                         | 'sha224'
                         | 'sha224'
                         | 'md4'
                         | 'sha512'
                         | 'rsa-sha256'
                         | 'dsa-sha'
                         | 'sha1WithRSAEncryption'
                         | 'md4'
                         | 'ssl3-sha1'
                         | 'ripemd160'
                         | 'sha'
                         | 'sha384'
                         | 'sha1'
                         | 'ssl3-md5'
                         | 'sha256'
                         | 'sha384WithRSAEncryption'
                         | 'sha512'
                         | 'dsa-sha1-old'
                         | 'dsaWithSHA1'
                         | 'ecdsa-with-SHA1'
                         | 'whirlpool'
                         | 'rsa-ripemd160'
                         | 'rmd160'
                         | 'ripemd160'
                         | 'rsa-sha1-2'
                         | 'rsa-sha1'
                         | 'dsaWithSHA'
                         | 'md5WithRSAEncryption'
                         | 'dss1'
                         | 'rsa-md5'
                         | 'dsaEncryption'
                         | 'ripemd'
                         | 'md4WithRSAEncryption'
                         | 'dsa'
                         | 'sha512WithRSAEncryption'
                         | 'sha'
                         | 'dss1'
                         | 'rsa-sha224'
                         | 'rsa-sha512'
                         | 'sha256'
                         | 'rsa-sha384'
                         | 'sha224WithRSAEncryption'
                         | 'rsa-sha'
                         | 'shaWithRSAEncryption'
                         | 'sha256WithRSAEncryption'
                         | 'dsa-sha1'
                         | 'rsa-md4'.


-record(addr, {host :: string()
              ,user :: string()
              ,password :: string()
              ,scheme :: scheme()
              ,port :: non_neg_integer()
              ,transport_param :: transport()
              ,ttl :: byte()
              ,user_p :: string()
              ,method :: sip_method()
              ,maddr :: string()
              ,lr :: boolean()
              ,extension :: [generic_param()]}).

-record(hd_via, {protocol = sip :: scheme()
                ,version :: float()
                ,transport :: transport()
                ,branch :: string()
                ,sent_by_host :: inet:hostname()
                ,sent_by_port :: inet:port_number()
                ,ttl :: byte()
                ,maddr :: string()
                ,received :: string()
                ,extension = [] :: [generic_param()]}).

-record(hd_max_forwards, {num :: non_neg_integer()}).

-record(hd_call_id, {id :: string()}).

-record(hd_cseq, {num :: non_neg_integer()
                 ,method :: sip_method()}).

-record(hd_allow, {methods :: [sip_method()]}).

-record(hd_supported, {options :: [string()]}).

-record(hd_user_agent, {val :: [{Product :: string(), Comment :: string()}]}).

-record(hd_content_length, {num :: non_neg_integer()}).

-record(hd_content_disposition, {type :: session | render | icon | alert
                                ,handling :: undefined | required | optional}).

-record(hd_content_type, {type :: text | image | audio | video | application | message | multipart
                         ,subtype :: string()
                         ,params :: [generic_param()]}).

-record(hd_contact, {display_name :: string()
                    ,addr :: #addr{}
                    ,params :: [generic_param()]
                    ,q :: float()
                    ,expires :: non_neg_integer()}).

-record(hd_from, {addr :: #addr{}
                 ,params :: [generic_param()]
                 ,tag :: string()}).

-record(hd_to, {addr :: #addr{}
               ,params :: [generic_param()]
               ,tag :: string()}).

-record(hd_authorization, {realm :: string()
                          ,username :: string()
                          ,algorithm :: digest_algorithm()
                          ,nonce :: string()
                          ,cnonce :: string()
                          ,nc :: string()
                          ,uri :: #addr{}
                          ,response :: string()
                          ,auth_param :: [generic_param()]}).

-record(hd_www_authenticate, {realm :: string()
                             ,domain :: string()
                             ,nonce :: string()
                             ,opaque :: string()
                             ,stale :: boolean()
                             ,algorithm :: digest_algorithm()
                             ,qop_options :: auth | auth_init
                             ,auth_param :: [generic_param()]}).

-record(hd_proxy_authenticate, {realm :: string()
                             ,domain :: string()
                             ,nonce :: string()
                             ,opaque :: string()
                             ,stale :: boolean()
                             ,algorithm :: digest_algorithm()
                             ,qop_options :: auth | auth_init
                             ,auth_param :: [generic_param()]}).

-type sip_header() :: #hd_via{}
                    | #hd_max_forwards{}
                    | #hd_to{}
                    | #hd_from{}
                    | #hd_call_id{}
                    | #hd_cseq{}
                    | #hd_authorization{}
                    | #hd_contact{}
                    | #hd_allow{}
                    | #hd_supported{}
                    | #hd_user_agent{}
                    | #hd_content_length{}
                    | #hd_www_authenticate{}
                    | #hd_proxy_authenticate{}
                    | #hd_content_type{}
                    | #hd_content_disposition{}.

-record(status_line, {code    :: code()
                     ,phrase  :: string()
                     ,version :: float()}).

-record(request_line, {method  :: sip_method()
                      ,ruri    :: #addr{}
                      ,version :: float()}).

-record(sip_req, {method :: sip_method()
                 ,ruri :: #addr{}
                 ,version :: float()
                 ,headers :: [sip_header()]
                 ,body :: string()}).

-record(sip_resp, {code :: code()
                  ,phrase :: string()
                  ,version :: float()
                  ,headers :: [sip_header()]
                  ,body :: string()}).

-endif.
