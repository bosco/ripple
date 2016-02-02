-module(node).
-export([create/1]).
-include("ripple.hrl").

count_votes(Knowledge) ->
	count_votes(Knowledge, {0, 0, 0}).
count_votes([], Tally) ->
	Tally;
count_votes([{_, 0}|Tail], {Undecided, For, Against}) ->
	count_votes(Tail, {Undecided + 1, For, Against});
count_votes([{_, 1}|Tail], {Undecided, For, Against}) ->
	count_votes(Tail, {Undecided, For + 1, Against});
count_votes([{_, -1}|Tail], {Undecided, For, Against}) ->
	count_votes(Tail, {Undecided, For, Against + 1}).

verify_sig(_, _, _, false) ->
	io:format("Dropping message from node that isn't in UNL~n", []),
	false;
verify_sig(_, Msg, Sig, Node) ->
	crypto:verify(?sig_algo, ?sig_digest, Msg, Sig, [Node#node_info.public_key, ?key_params]).

make_signed_message(Id, Msg, Private_key) ->
	Bin_msg = term_to_binary(Msg),
	Sig = crypto:sign(?sig_algo, ?sig_digest, Bin_msg, [Private_key, ?key_params]),
	#signed_message{id=Id, sig=Sig, msg=Bin_msg}.
	
create(Supervisor) ->
	Pid = self(),
	{Public_key, Private_key} = crypto:generate_key(?key_type, ?key_params),
	Id = crypto:hash(?hash_type, Public_key),
	Node_info = #node_info{id=Id, pid=Pid, public_key=Public_key},
	Supervisor ! Node_info,
	receive_msg([], Node_info, Private_key, [], 0). 

receive_msg(Unl, Node_info, Private_key, Knowledge, Start_time) ->
	receive
		{start, New_unl} ->
			%% Right now everyone is voting FOR
			New_knowledge = [{Node_info#node_info.id, 1} |
					lists:map(fun(Node) -> {Node#node_info.id, 0} end, New_unl)],
			New_start_time = erlang:system_time(milli_seconds),
			Msg = make_signed_message(Node_info#node_info.id, #vote{position=true}, Private_key),
			lists:foreach(fun(Node) -> Node#node_info.pid ! Msg end, New_unl);
		#signed_message{id=Id, sig=Sig, msg=Msg} ->
			Node = lists:keyfind(Id, 2, Unl),
			Sig_check = verify_sig(Unl, Msg, Sig, Node),
			if
				Sig_check ->
					case binary_to_term(Msg) of
						#vote{position=Position} when Position == true ->
							Updated_knowledge = lists:keyreplace(Id, 1, Knowledge, {Id, 1});
						#vote{} ->
							Updated_knowledge = lists:keyreplace(Id, 1, Knowledge, {Id, -1})
					end,

					%% Every 1/4 of a second you need one more vote to change our vote
					Time = erlang:system_time(milli_seconds),
					Min_votes = length(Updated_knowledge) / 2,
					Required = Min_votes + ((Time - Start_time) / 250),
					Tally = count_votes(Updated_knowledge),
					io:format("~p Tally: ~p Required: ~p~n", [Node_info#node_info.pid, Tally, Required]),
					
					case count_votes(Updated_knowledge) of
						{Undecided, For, _} when Undecided < Min_votes, For > Required ->
							io:format("Changing my vote to for.~n", []);
						{Undecided, _, _} when Undecided < Min_votes ->
							io:format("Changing my vote to against.~n", []);
						_ ->
							io:format("We don't have enough votes to change.~n", [])
					end;
				true ->
					io:format("Invalid signature~n", []),
					New_knowledge = Knowledge
			end,
			New_unl = Unl,
			New_start_time = Start_time
	end,
	receive_msg(New_unl, Node_info, Private_key, New_knowledge, New_start_time).
