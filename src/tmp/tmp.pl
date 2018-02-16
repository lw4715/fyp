requireHighResource(Att) :- highVolumeAttack(Att), longDurationAttack(Att). %O9
governmentLinked(P, C) :- geolocatedInGovFacility(P, C). %O10
governmentLinked(P, C) :- publicCommentsRelatedToGov(P, C). %O11


% strategic
isCulprit(G, Att) :- claimedResponsibility(G, Att). % S1
isCulprit(C, Att) :- hasMotive(C, Att), hasCapability(C, Att).% S2
% ex2
isCulprit(C, Att) :- hasMotive(C, Att), culpritIsFrom(C, Att). %S3
not isCulprit(C, Att) :- culpritIsFrom(C, Att), not hasCapability(C, Att). %S4
isCulprit(C, Att) :- governmentLinked(P, C), identifiedIndividualInAttack(P, Att). %S5

% constraints
:- isCulprit(X, Att), isCulprit(Y, Att), X != Y.
