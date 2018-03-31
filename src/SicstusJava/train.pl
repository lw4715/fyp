% train.pl

connected(From, To, Path) :-
        connected(From, To, Path, [From]).

connected(To, To, [To], _).
connected(From, To, [From|Path], Visited) :-
        (   connection(From, Via)
        ;   connection(Via, From)
        ),
        not_visited(Visited, Via),
        connected(Via, To, Path, [Via|Visited]).

connection('Stockholm', 'Katrineholm').
connection('Stockholm', 'Vasteras').
connection('Stockholm', 'Uppsala').
connection('Uppsala', 'Vasteras').
connection('Katrineholm', 'Hallsberg').
connection('Katrineholm', 'Linkoping').
connection('Hallsberg', 'Kumla').
connection('Hallsberg', 'Goteborg').
connection('Orebro', 'Vasteras').
connection('Orebro', 'Kumla').

not_visited([], _).
not_visited([X|Visited], Y) :- X \== Y, not_visited(Visited, Y).