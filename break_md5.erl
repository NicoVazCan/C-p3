-module(break_md5).
-define(PASS_LEN, 6).
-define(UPDATE_BAR_GAP, 1000).
-define(BAR_SIZE, 40).
-define(NPROCS, 10).

-export([break_md5s/1, break_md5/1, break_md5/3, pass_to_num/1, num_to_pass/1]).
-export([progress_loop/2]).
-export([break_md5_server/4, init_proc/5]).

% Base ^ Exp

pow_aux(_Base, Pow, 0) -> Pow;
pow_aux(Base, Pow, Exp) when Exp rem 2 == 0 ->
    pow_aux(Base*Base, Pow, Exp div 2);
pow_aux(Base, Pow, Exp) -> pow_aux(Base, Base * Pow, Exp - 1).

pow(Base, Exp) -> pow_aux(Base, 1, Exp).

%% Number to password and back conversion

num_to_pass_aux(_N, 0, Pass) -> Pass;
num_to_pass_aux(N, Digit, Pass) ->
    num_to_pass_aux(N div 26, Digit - 1, [$a + N rem 26 | Pass]).

num_to_pass(N) -> num_to_pass_aux(N, ?PASS_LEN, []).

pass_to_num_aux([], Num) -> Num;
pass_to_num_aux([C|T], Num) -> pass_to_num_aux(T, Num*26 + C-$a).

pass_to_num(Pass) -> pass_to_num_aux(Pass, 0).

%% Hex string to Number

hex_char_to_int(N) ->
    if (N >= $0) and (N =< $9) -> N-$0;
       (N >= $a) and (N =< $f) -> N-$a+10;
       (N >= $A) and (N =< $F) -> N-$A+10;
       true -> throw({not_hex, [N]})
    end.

hex_string_to_num_aux([], Num) -> Num;
hex_string_to_num_aux([Hex|T], Num) ->
    hex_string_to_num_aux(T, Num*16 + hex_char_to_int(Hex)).

hex_string_to_num(Hex) -> hex_string_to_num_aux(Hex, 0).

%% Progress bar runs in its own process

progress_loop(N, Bound) ->
    receive
        stop -> ok;
        {progress_report, Checked} ->
            N2 = N + Checked,
            Full_N = N2 * ?BAR_SIZE div Bound,
            Full = lists:duplicate(Full_N, $=),
            Empty = lists:duplicate(?BAR_SIZE - Full_N, $-),
            io:format("\r[~s~s] ~.2f%", [Full, Empty, N2/Bound*100]),
            progress_loop(N2, Bound)
    end.

%% break_md5/2 iterates checking the possible passwords

break_md5(N, Bound, Server_Pid) ->
    receive
        [] -> 
            Server_Pid! {exit, self()};
        Hashes when N < Bound ->
            Pass = num_to_pass(N),
            Hash = crypto:hash(md5, Pass),
            Num_Hash = binary:decode_unsigned(Hash),
            case lists:member(Num_Hash, Hashes) of
                true ->
                    io:format("\e[2K\r~.16B: ~s~n", [Num_Hash, Pass]),
                    Server_Pid! {Num_Hash, self()};
                false ->
                    Server_Pid! {not_found, self()}
            end,
            break_md5(N+1, Bound, Server_Pid);
        _ ->
            Server_Pid! {exit, self()}
    end.

%% Break a list of hashes

break_md5s(Hashes) ->
    Bound = pow(26, ?PASS_LEN),
    Progress_Pid = spawn(?MODULE, progress_loop, [0, Bound]),
    Num_Hashes = lists:map(fun hex_string_to_num/1, Hashes),
    Proc_List = init_proc(0, Num_Hashes, Bound div ?NPROCS, Bound rem ?NPROCS, self()),
    lists:foreach(fun(Proc_Pid) -> Proc_Pid! Num_Hashes end, Proc_List),
    Res = break_md5_server(0, Proc_List, Num_Hashes, Progress_Pid),
    Progress_Pid ! stop,
    Res.

%% Break a single hash

break_md5(Hash) -> break_md5s([Hash]).

init_proc(K, Num_Hashes, Proc_Bound, Rem, Server_Pid) ->
    if
        K == ?NPROCS-1 ->
            [spawn(?MODULE, break_md5, [K*Proc_Bound, (K+1)*Proc_Bound+Rem, Server_Pid])];
        true ->
            [spawn(?MODULE, break_md5, [K*Proc_Bound, (K+1)*Proc_Bound, Server_Pid]) |
                init_proc(K+1, Num_Hashes, Proc_Bound, Rem, Server_Pid)]
    end.
break_md5_server(_, _, [], _) -> ok;
break_md5_server(_, [], Num_Hashes, _) -> {not_found, Num_Hashes};
break_md5_server(N, Proc_List, Num_Hashes, Progress_Pid) ->
    if N rem ?UPDATE_BAR_GAP == 0 ->
            Progress_Pid ! {progress_report, ?UPDATE_BAR_GAP};
       true -> ok
    end,
    receive
        {not_found, Proc_Pid} -> 
            Proc_Pid! Num_Hashes,
            break_md5_server(N+1, Proc_List, Num_Hashes, Progress_Pid);
        {exit, Proc_Pid} ->
            break_md5_server(N+1, lists:delete(Proc_Pid, Proc_List), Num_Hashes, Progress_Pid);
        {Hash, Proc_Pid} ->
            Next_Hashes = lists:delete(Hash, Num_Hashes),
            Proc_Pid! Next_Hashes,
            break_md5_server(N+1, Proc_List, Next_Hashes, Progress_Pid)
    end.