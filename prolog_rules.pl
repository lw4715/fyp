requireHighResource(O) <- usesManyZeroDayVulnerabilities(O).


hasResources(X) <- isCountry(X); isLargeOrganization(X).


hasCapability(X, O) <- hasResources(X), requireHighResource(O).
hasCapability(_, O) <- not(requireHighResource(O)).

not(isCulprit(X)) <- not(requireHighResource()), isCountry(X).

# X is country
hasMotive(X) <- conflict(X, Y), allVictimsSameCountry(Victims, Y).
# X is organization
hasMotive(X) <- industryOf(X) = Y, allVictimsSameIndustry(Victims, Y).
allVictimsSameCountry([], Y).
allVictimsSameCountry([V | Vs], Y) :- countryOf(V, Y), allVictimsSameCountry(Vs, Y).
allVictimsSameIndustry([], Y).
allVictimsSameIndustry([V | Vs], Y) :- industryOf(V, Y), allVictimsSameIndustry(Vs, Y).

#E1 is current cyber attack, E2 are previous attacks
#isCulprit(X) refers to THIS event
#if given argument, refer to previous events
isCulprit(X) <- similarCode(E1, E2), isCulprit(X, E2).

culpritIsFrom(C) <- originFrom(IP, C).
not(culpritIsFrom(C)) <- spoofed(IP).

culpritIsFrom(C) <- language(L), nativeLanguage(C, L).

isCulprit(X) <- culpritIsFrom(X).

# partOf(X, Y) returns True if X is part of the group Y
isCulprit(C) <- linksWithGov(X, C), partOf(X, culprit).

isCulprit(X) <- ownedUp(X).
isCulprit(X) <- hasCapability(X), hasMotive(X).



############## from 1/2/18 meeting

has_capability(Att, X) :- sophisticated(Att), has_resouces(X).
has_capability(Att, X) :- not sophisticated(Att).
has_motive(Att, C) :- has_political_motive(C, T), target(Att, C).
sophisticated(Att) :- many_zero_day_vul(Att).
is_culprit(Att, C) :- has_motive(Att, C), has_capability(Att, C).
