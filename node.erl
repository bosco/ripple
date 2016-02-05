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

%%% Updates sends out our vote and updates our knowledge
vote(Node_info, Knowledge, Private_key, Vote, Node_list) ->
	io:format("~p voting ~p~n", [Node_info#node_info.pid, Vote]),
	Msg = make_signed_message(Node_info#node_info.id, #vote{position=Vote}, Private_key),
	lists:foreach(fun(Node) -> Node#node_info.pid ! Msg end, Node_list),
	if 
		Vote ->
			lists:keyreplace(Node_info#node_info.id, 1, Knowledge, {Node_info#node_info.id, 1});
		true ->
			lists:keyreplace(Node_info#node_info.id, 1, Knowledge, {Node_info#node_info.id, -1})
	end.

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
		{start, New_unl, Vote} ->
			Updated_knowledge = [{Node_info#node_info.id, 0} |
					lists:map(fun(Node) -> {Node#node_info.id, 0} end, New_unl)],
			New_start_time = erlang:system_time(milli_seconds),
			%% Right now everyone is voting FOR
			New_knowledge = vote(Node_info, Updated_knowledge, Private_key, Vote, New_unl);
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

					%% You need 50% + one vote for every 1/4 of a second to change our vote
					Time = erlang:system_time(milli_seconds),
					Min_votes = length(Updated_knowledge) / 2,
					Required_to_change = Min_votes + ((Time - Start_time) / 250),
					%% You need 80% of the vote to reach consensus
					Required_to_stop = length(Updated_knowledge) * 0.8,
					Tally = count_votes(Updated_knowledge),
					io:format("~p Tally: ~p Required_to_change: ~p Required_to_stop: ~p~n",
						[Node_info#node_info.pid, Tally, Required_to_change, Required_to_stop]),
					
					case count_votes(Updated_knowledge) of
						{_, _, Against} when Against >= Required_to_stop ->
							io:format("~p Consesus reached: AGAINST~n", [Node_info#node_info.pid]),
							New_knowledge = Updated_knowledge,
							exit(normal);
						{_, For, _} when For > Required_to_stop -> 
							io:format("~p Consesus reached: FOR~n", [Node_info#node_info.pid]),
							New_knowledge = Updated_knowledge,
							exit(normal);
						{_, For, _} when For > Required_to_change ->
							New_knowledge = vote(Node_info, Updated_knowledge, Private_key, true, Unl);
						_ ->
							io:format("~p We don't have enough votes to change.~n", [Node_info#node_info.pid]),
							New_knowledge = Updated_knowledge
					end;
				true ->
					io:format("Invalid signature~n", []),
					New_knowledge = Knowledge
			end,
			New_unl = Unl,
			New_start_time = Start_time
		after 250 -> %% if we get hung up, throw out our last vote again after waiting a bit
			case lists:keyfind(Node_info#node_info.id, 1, Knowledge) of
				{_, 1} ->
					Last_vote = true;
				{_, -1} ->
					Last_vote = false
			end,
			New_knowledge = vote(Node_info, Knowledge, Private_key, Last_vote, Unl),
			New_unl = Unl,
			New_start_time = Start_time
	end,
	receive_msg(New_unl, Node_info, Private_key, New_knowledge, New_start_time).
