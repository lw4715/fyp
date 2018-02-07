:- multifile action/4.
:- dynamic action/4.

action(tell(c1,c2,request(r1),d,t),g1,nil,5<T).
action(tell(thanks),g1,nil,10).