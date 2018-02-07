%:- module(goals).

:- multifile goal/4.
:- dynamic goal/4.

goal(g0,problem_fixed(p2,t),nil,5<T). 
goal(g1,get_resource(R1,T1),g0,5<T1). 
goal(g2,get_resource(R2,T2),g0,5<T2).
goal(g3,tell(thanks),g1,6). 