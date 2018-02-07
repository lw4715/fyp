:- module(kbplan).


holds_at(G,T2) :- happens(A,T1),T1<T2,initiates(A,G),not(clipped(T1,G,T2)).

abducible(assume_happens). 