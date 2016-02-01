-module(peer).
-export([create/0]).
-include("ripple.hrl").

cookie() -> 
	rand:uniform(?max_cookie).

get_peer_info(Us, Them) ->
	Cookie = cookie(),
	Them#peer_info.pid ! #get_peer_info{peer=Us, cookie=Cookie},
	receive
		#signed_message{sig=Sig, msg=Bin_msg, cookie=Cookie} ->
			Peer_info = binary_to_term(Bin_msg),
			Bad_sig = not crypto:verify(?sig_algo, ?sig_digest, Bin_msg, Sig,
							Peer_info#peer_info.public_key),
			Bad_hash = crypto:hash(?hash_type, Peer_info#peer_info.public_key) /=
						Peer_info#peer_info.hash,
			if
				Bad_sig ->
					bad_signature;
				Bad_hash ->
					bad_hash;
				true ->
					Peer_info
			end
	after ?receive_timeout ->
		timeout
	end.

send_signed(Peer, Msg, Private_key, Cookie) ->
	Bin_msg = term_to_binary(Msg),
	Sig = crypto:sign(?sig_algo, ?sig_digest, Bin_msg, [Private_key, ?key_params]),
	Peer#peer_info.pid ! #signed_message{sig=Sig, msg=Bin_msg, cookie=Cookie}.
	
create() ->
	Pid = self(),
	{Public_key, Private_key} = crypto:generate_key(?key_type, ?key_params),
	Hash = crypto:hash(?hash_type, Public_key),
	Peer_info = #peer_info{pid=Pid, hash=Hash, public_key=Public_key},
	receive_msg([], Peer_info, Private_key). 

receive_msg(Unl, Peer_info, Private_key) ->
	receive
		#signed_message{sig=Sig, msg=Msg, cookie=Cookie} ->
			io:format("Got signed message~n", []);
		#get_peer_info{peer=Peer, cookie=Cookie} ->
			io:format("Got request for peer info~n", []),
			io:format("Sending a signed message with my peer info~n", []),
			send_signed(Peer, Peer_info, Private_key, Cookie)
	end.
