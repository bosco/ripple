-module(network).
-export([start/0]).
-include("ripple.hrl").

get_nodes_list(Nodes, 0) ->
	Nodes;
get_nodes_list(Nodes, N) ->
	receive
		Node ->
			get_nodes_list([Node|Nodes], N-1)
	end.
		
start() ->
	start(10),
	Nodes = get_nodes_list([], 10),
	%% Give every node a UNL without themselves in it
	lists:foreach(fun(Node) -> Node#node_info.pid ! {start, lists:delete(Node, Nodes)} end, Nodes).
start(0) ->
	done;
start(N) ->
	spawn_link(node, create, [self()]),
	start(N-1).
