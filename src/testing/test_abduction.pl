:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/lib/gorgias.pl').
:- compile('/homes/lw4715/Computing/FYP/gorgias-src-0.6d/ext/lpwnf.pl').

rule(r1, soreElbow, [tennisElbow]).
rule(r2, soreElbow, [soreJoint]).
rule(r3, tennisPlayer, [tennisElbow]).
rule(r4, soreJoint, [arthritis, untreated]).
rule(fact, untreated, []).
rule(ic, false, [soreJoint]).

abducible(arthritis, []).

abducible(soreJoint, []).
abducible(tennisElbow, []).
