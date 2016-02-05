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
	start_nodes(Nodes, Nodes, 5).
start(0) ->
	done;
start(N) ->
	spawn_link(node, create, [self()]),
	start(N-1).

%% Sends every node the start command, a UNL without themselves in it,
%% and their initial voting position
start_nodes([], _, _) ->
	done;
start_nodes([Node | Tail ], Nodes, 0) ->
	Node#node_info.pid ! {start, lists:delete(Node, Nodes), false},
	start_nodes(Tail, Nodes, 0);
start_nodes([Node | Tail ], Nodes, True_nodes) ->
	Node#node_info.pid ! {start, lists:delete(Node, Nodes), true},
	start_nodes(Tail, Nodes, True_nodes - 1).
