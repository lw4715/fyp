:- multifile rule/3.
%% countries

%% prominent players (APT)
%% https://www.fireeye.com/current-threats/apt-groups.html
%% https://www.darkreading.com/endpoint/8-active-apt-groups-to-watch/d/d-id/1325161?image_number=1

% North Korea
prominentGroup(lazarusGrp).
groupOrigin(lazarusGrp, northkorea).
malwareLinkedTo('Backdoor.Duuzer', lazarusGrp).
malwareLinkedTo('Backdoor.Destover', lazarusGrp).
malwareLinkedTo('Infostealer.Fakepude', lazarusGrp).
malwareLinkedTo('Backdoor.Contopee', lazarusGrp).

% USA
prominentGroup(equationGrp).
groupOrigin(equationGrp, usa).
pastTargets(equationGrp, [iran, russia, pakistan, afghanistan, india, syria, mali]).
%% https://en.wikipedia.org/wiki/Equation_Group

% USSR
prominentGroup(anglerEK).
groupOrigin(anglerEK, ussr).
groupAttackMethods(anglerEK, [driveByDownloads]).
pastMotives(anglerEK, [undergroundBusiness]).

%% China
prominentGroup(deepPanda).
groupOrigin(deepPanda, china).
groupAttackMethods(deepPanda, [zeroday, wateringHole, customMalware]).
pastTargets(deepPanda, [aerospace, energy, healthcare]).
pastMotives(deepPanda, [cyberespionage]).

prominentGroup(butterfly).
groupOrigin(butterfly, china).
groupAttackMethods(butterfly, [zeroday, customMalware]).
pastTargets(butterfly, [twitter, facebook, apple, microsoft, pharmaceutical, technology, law, oil, preciousMetalMining]).
pastMotives(butterfly, [cyberespionage, undergroundBusiness]).

%% Eastern Europe
prominentGroup(dragonfly).
groupOrigin(dragonfly, eastEurope).
groupAttackMethods(dragonfly, [spamEmail, wateringHole, customMalware]).
pastTargets(dragonfly, [defense, aerospace, energy]).
pastMotives(dragonfly, [cyberespionage, spy, sabotage]).
%% ?

prominentGroup(govRAT).
groupAttackMethods(govRAT, [clientSideExploits]).
pastTargets(govRAT, [govOfficials, militaryOfficials, enterprises]).
pastMotives(govRAT, [cyberespionage]).

prominentGroup(pawnStorm).
groupAttackMethods(pawnStorm, [spearphishing, phishingWebsites, ios, exploits, zeroday]).
pastTargets(pawnStorm, [nato, govOfficials, militaryOfficials, russia, ukraine]).
pastMotives(pawnStorm, [cyberespionage]).

prominentGroup(waterbug).
groupAttackMethods(waterbug, [zeroday, email, stolenCertificates, wateringHole]).
pastTargets(waterbug, [govInstitutions, embassies, education, research]).
pastMotives(waterbug, [cyberespionage, spy, intelligenceGathering]).

%% Background
listCountries([china, israel, iran, usa, united_kingdom, northkorea, southkorea]).
listHasResources([china, israel, iran, usa, northkorea]).
listIndustries([infocomm]).
listChineseCountries([china]).
listEnglishCountries([usa, united_kingdom]).

country(X) :- listCountries(L), member(X, L).
industry(X) :- listIndustries(L), member(X, L).
hasResources(X) :- listHasResources(L), member(X, L).
firstLanguage(chinese, X) :- listChineseCountries(L), member(X, L).
firstLanguage(english, X) :- listEnglishCountries(L), member(X, L).
% firstLanguage(french, X) :- member(X, listFrenchCountries).
% firstLanguage(arabic, X) :- member(X, listArabicCountries).

isCulprit(equationGroup, flameattack).
malwareUsedInAttack(flame, flameattack).

isInfrastructure(nuclear).
isInfrastructure(electricity).
isInfrastructure(water).
informationRich(banking).
informationRich(infocomm).
informationRich(consumer).

possibleMotive(sabotage, Att) :- isInfrastructure(Ind), industry(Ind, V), target(V, Att).
possibleMotive(espionage, Att) :- informationRich(Ind), industry(Ind, V), target(V, Att).

%% past cases
%% flame
%% rule(f6, isCulprit(equationGroup,flameattack), []).
isCulprit([usa,israel],flameattack).
target(middleeast,flameattack).
malwareUsedInAttack(flame,flameattack).
ccServer(gowin7, flame).
ccServer(secuurity, flame).
domainRegisteredDetails(gowin7, "adolph dybevek", "prinsen gate 6").
domainRegisteredDetails(secuurity, "adolph dybevek", "prinsen gate 6").
addressType("prinsen gate 6", hotel).




