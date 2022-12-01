-module(break_md5).
-define(PASS_LEN, 6).
-define(UPDATE_BAR_GAP, 1000).
-define(BAR_SIZE, 40).
-define(NPROCS, 2).

-export([break_md5s/1, break_md5/1, pass_to_num/1, num_to_pass/1]).
-export([progress_loop/2]).
-export([break_md5/5, break_md5/6]).

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
break_md5(Hashes, N, Bound, Progress_Pid, Main_Pid) ->
    receive
        Proc_List -> break_md5(Hashes, N, Bound, Progress_Pid, Proc_List, Main_Pid)
    end.
break_md5([], _, _, _, _, _) -> ok; % No more hashes to find
break_md5(_, N, N, _, Proc_List, Main_Pid) ->
    Main_Pid! {not_found, self()},  % Checked every possible password
    notify_proc(mod, Proc_List); % Tells all processes this one ended
break_md5(Hashes, N, Bound, Progress_Pid, Proc_List, Main_Pid) ->
    if N rem ?UPDATE_BAR_GAP == 0 ->
            Progress_Pid ! {progress_report, ?UPDATE_BAR_GAP};
        true -> ok
    end,
    Pass = num_to_pass(N),
    Hash = crypto:hash(md5, Pass),
    Num_Hash = binary:decode_unsigned(Hash),
    case lists:member(Num_Hash, Hashes) of
        true ->
            io:format("\e[2K\r~.16B: ~s~n", [Num_Hash, Pass]),
            Main_Pid! {found, Num_Hash},
            notify_proc(mod, Proc_List); % Tells all processes itself included
                                         % that a hash has been found
        false ->
            Main_Pid! {ignore, []},
            notify_proc(ignore, Proc_List)  
    end,
    Msgs = receive_noti(?NPROCS),
    break_md5(Hashes, N+1, Bound, Progress_Pid, Proc_List, Main_Pid)
    case lists:member(mod, Msgs) of
        true ->
            receive
                {New_Hashes, New_Proc_List} -> 
                    break_md5(New_Hashes, N+1, Bound, Progress_Pid, New_Proc_List, Main_Pid)
            end;
        false -> 
            break_md5(Hashes, N+1, Bound, Progress_Pid, Proc_List, Main_Pid)
    end.


%% Break a list of hashes

break_md5s(Hashes) ->
    Bound = pow(26, ?PASS_LEN),
    Progress_Pid = spawn(?MODULE, progress_loop, [0, Bound]),
    Num_Hashes = lists:map(fun hex_string_to_num/1, Hashes),
    Proc_List = init_proc(Num_Hashes, Bound div ?NPROCS, Bound div ?NPROCS, Progress_Pid, self()),
    notify_proc(Proc_List, Proc_List),
    Res = info_server(Num_Hashes, Proc_List),
    Progress_Pid ! stop,
    Res.

%% Break a single hash

break_md5(Hash) -> break_md5s([Hash]).

% Spawns NPROCS processes to break all the hashes

init_proc(Num_Hashes, Proc_Bound, Rem, Progress_Pid, Main_Pid) ->
    init_proc(0, Num_Hashes, Proc_Bound, Rem, Progress_Pid, Main_Pid).
init_proc(K, Num_Hashes, Proc_Bound, Rem, Progress_Pid, Main_Pid) ->
    if
        K == ?NPROCS-1 ->
            [spawn(?MODULE, break_md5,
                   [Num_Hashes, K*Proc_Bound, (K+1)*Proc_Bound+Rem, Progress_Pid, Main_Pid])];
        true ->
            [spawn(?MODULE, break_md5,
                   [Num_Hashes, K*Proc_Bound, (K+1)*Proc_Bound, Progress_Pid, Main_Pid])|
                        init_proc(K+1, Num_Hashes, Proc_Bound, Rem, Progress_Pid, Main_Pid)]
    end.

notify_proc(_, []) -> ok;
notify_proc(Msg, [Pid|Proc_List]) -> Pid! Msg, notify_proc(Msg, Proc_List).

receive_noti(K) when K > 0 ->
    receive
        Msg -> [Msg|receive_noti(K-1)]
    end;
receive_noti(0) -> [].

% Tells all processes about the remainig hashes and processes

info_server([], _) -> ok;
info_server(Hashes, []) -> {not_found, Hashes};
info_server(Hashes, Proc_List) ->
    Msgs = receive_noti(?NPROCS),
    case lists:all(fun({Msg, _}) -> Msg == ignore end, Msgs) of
        false ->
            {New_Hashes, New_Proc_List} = info_process(Msgs, {Hashes, Proc_List}),
            notify_proc({New_Hashes, New_Proc_List}, New_Proc_List),
            info_server(New_Hashes, New_Proc_List);
        true ->
            info_server(Hashes, Proc_List)
    end.

info_process([], Res) -> Res;
info_process([Msg|Msgs], {Hashes, Proc_List}) ->
    case Msg of
        {not_found, Pid} ->
            info_process(Msgs, {Hashes, (lists:delete(Pid, Proc_List))});
        {found, Hash} ->
            info_process(Msgs, {(lists:delete(Hash, Hashes)), Proc_List});
        {ignore, []} ->
            info_process(Msgs, {Hashes, Proc_List})
    end.
