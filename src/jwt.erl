%%
%% JWT Library for Erlang.
%% Written by Peter Hizalev at Kato (http://kato.im)
%% Rewritten by Yuri Artemev (http://artemff.com)
%%

-module(jwt).

-export([decode/2, decode/3]).
-export([encode/3, encode/4]).

-define(HOUR, 3600).
-define(DAY, 3600 * 60).

%%
%% API
%%

encode(Alg, ClaimsSet, Key) ->
    Claims = base64url:encode(jsx:encode(ClaimsSet)),
    Header = base64url:encode(jsx:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", Claims/binary>>,
    case jwt_sign(Alg, Payload, Key) of
        undefined -> {error, algorithm_not_supported};
        Signature -> {ok, <<Payload/binary, ".", Signature/binary>>}
    end.

encode(Alg, ClaimsSet, Expiration, Key) ->
    Claims = base64url:encode(jsx:encode(jwt_add_exp(ClaimsSet, Expiration))),
    Header = base64url:encode(jsx:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", Claims/binary>>,
    case jwt_sign(Alg, Payload, Key) of
        undefined -> {error, algorithm_not_supported};
        Signature -> {ok, <<Payload/binary, ".", Signature/binary>>}
    end.

decode(Token, Key) ->
    case split_token(Token) of
        SplitToken = [Header, Claims | _] ->
            case decode_jwt(SplitToken) of
                {#{<<"typ">> := Type, <<"alg">> := Alg} = _Header, ClaimsJSON, Signature} ->
                    case jwt_check_sig(Type, Alg, Header, Claims, Signature, Key) of
                        false -> {error, invalid_signature};
                        true ->
                            case jwt_is_expired(ClaimsJSON) of
                                true  -> {error, expired};
                                false -> {ok, ClaimsJSON}
                            end
                    end;
                invalid -> {error, invalid_token}
            end;
        _ -> {error, invalid_token}
    end.

% When there are multiple issuers and keys are on a per issuer bases
% then apply those keys instead
decode(Token, DefaultKey, IssuerKeyMapping) ->
    case split_token(Token) of
        SplitToken = [Header, Claims | _] ->
            case decode_jwt(SplitToken) of
                {#{<<"typ">> := Type, <<"alg">> := Alg} = _Header, ClaimsJSON, Signature} ->
                    Issuer = maps:get(<<"iss">>, ClaimsJSON, undefined),
                    Key = maps:get(Issuer, IssuerKeyMapping, DefaultKey),
                    case jwt_check_sig(Type, Alg, Header, Claims, Signature, Key) of
                        false -> {error, invalid_signature};
                        true ->
                            case jwt_is_expired(ClaimsJSON) of
                                true  -> {error, expired};
                                false -> {ok, ClaimsJSON}
                            end
                    end;
                invalid -> {error, invalid_token}
            end;
        _ -> {error, invalid_token}
    end.



%%
%% Decoding helpers
%%

jsx_decode_safe(Bin) ->
    try
        jsx:decode(Bin, [return_maps])
    catch _ ->
        invalid
    end.

jwt_is_expired(#{<<"exp">> := Exp} = _ClaimsJSON) ->
    case (Exp - epoch()) of
        DeltaSecs when DeltaSecs > 0 -> false;
        _ -> true
    end;
jwt_is_expired(_) ->
    false.

jwt_check_sig(<<"JWT">>, Alg, Header, Claims, Signature, Key) ->
    case algorithm_to_crypto(Alg) of
        {hmac, _} ->
            Payload = <<Header/binary, ".", Claims/binary>>,
            jwt_sign(Alg, Payload, Key) =:= Signature;
        {ecdsa, Crypto} ->
            io:format("~p ~p ~p ~p~n", [Crypto, Header, Claims, Signature]),
            R = public_key:verify(<<Header/binary, ".", Claims/binary>>, Crypto, base64url:decode(Signature), Key),
						%io:format(R),
						R
    end;
jwt_check_sig(_, _, _, _, _, _) ->
    false.

split_token(Token) ->
    binary:split(Token, <<".">>, [global]).

decode_jwt([Header, Claims, Signature]) ->
    try
        [HeaderJSON, ClaimsJSON] =
            Decoded = [jsx_decode_safe(base64url:decode(X)) || X <- [Header, Claims]],
        case lists:any(fun(E) -> E =:= invalid end, Decoded) of
            true  -> invalid;
            false -> {HeaderJSON, ClaimsJSON, Signature}
        end
    catch _:_ ->
        invalid
    end;
decode_jwt(_) ->
    invalid.

%%
%% Encoding helpers
%%

jwt_add_exp(ClaimsSet, Expiration) ->
    Ts = epoch(),
    Exp = case Expiration of
        {hourly, Expiration0} -> (Ts - (Ts rem ?HOUR)) + Expiration0;
        {daily, Expiration0} -> (Ts - (Ts rem ?DAY)) + Expiration0;
        _ -> epoch() + Expiration
    end,        
    [{<<"exp">>, Exp} | ClaimsSet].

jwt_header(Alg) ->
    [ {<<"alg">>, Alg}
    , {<<"typ">>, <<"JWT">>}
    ].

%%
%% Helpers
%%

jwt_sign(Alg, Payload, Key) ->
    case algorithm_to_crypto(Alg) of
        undefined -> undefined;
        {hmac, Crypto} -> base64url:encode(crypto:hmac(Crypto, Key, Payload));
        {ecdsa, Crypto} ->
            Sig = case is_function(Key) of
                      true ->
                          Key(Payload, Crypto);
                      false ->
                          public_key:sign(Payload, Crypto, Key)
                  end,
            {'ECDSA-Sig-Value', R, S} = public_key:der_decode('ECDSA-Sig-Value', Sig),
            RBin = int_to_bin(R),
            SBin = int_to_bin(S),
            Size = 32,
            RPad = pad(RBin, Size),
            SPad = pad(SBin, Size),
            Signature = << RPad/binary, SPad/binary >>,
            base64url:encode(Signature);
        {rsa, Crypto} ->
            Signature = public_key:sign(Payload, Crypto, Key),
            base64url:encode(Signature)
    end.

algorithm_to_crypto(<<"HS256">>) -> {hmac, sha256};
algorithm_to_crypto(<<"HS384">>) -> {hmac, sha384};
algorithm_to_crypto(<<"HS512">>) -> {hmac, sha512};
algorithm_to_crypto(<<"ES256">>) -> {ecdsa, sha256};
algorithm_to_crypto(<<"RS256">>) -> {rsa, sha256};
algorithm_to_crypto(_)           -> undefined.

epoch() -> erlang:system_time(seconds).


%% @private
int_to_bin(X) when X < 0 -> int_to_bin_neg(X, []);
int_to_bin(X) -> int_to_bin_pos(X, []).

%% @private
int_to_bin_pos(0,Ds=[_|_]) ->
    list_to_binary(Ds);
int_to_bin_pos(X,Ds) ->
    int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bin_neg(-1, Ds=[MSB|_]) when MSB >= 16#80 ->
    list_to_binary(Ds);
int_to_bin_neg(X,Ds) ->
    int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

%% @private
pad(Bin, Size) when byte_size(Bin) =:= Size ->
    Bin;
pad(Bin, Size) ->
    pad(<< 0, Bin/binary >>, Size).
