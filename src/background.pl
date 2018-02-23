%% countries

%% prominent players (APT)
%% https://www.fireeye.com/current-threats/apt-groups.html
%% https://www.darkreading.com/endpoint/8-active-apt-groups-to-watch/d/d-id/1325161?image_number=1

% USA
prominentGroup(equationGrp).
country(equationGrp, usa).
pastTargets(equationGrp, [iran, russia, pakistan, afghanistan, india, syria, mali]).
%% https://en.wikipedia.org/wiki/Equation_Group

% USSR
prominentGroup(anglerEK).
country(anglerEK, ussr).
pastAttackMethods(anglerEK, [driveByDownloads]).
pastMotives(anglerEK, [undergroundBusiness]).

%% China
prominentGroup(blackVine).
country(blackVine, china).
pastAttackMethods(blackVine, [zeroday, wateringHole, customMalware]).
pastTargets(blackVine, [aerospace, energy, healthcare]).
pastMotives(blackVine, [cyberespionage]).

prominentGroup(butterfly).
country(butterfly, china).
pastAttackMethods(butterfly, [zeroday, customMalware]).
pastTargets(butterfly, [twitter, facebook, apple, microsoft, pharmaceutical, technology, law, oil, preciousMetalMining]).
pastMotives(butterfly, [cyberespionage, undergroundBusiness]).

%% Eastern Europe
prominentGroup(dragonfly).
country(dragonfly, eastEurope).
pastAttackMethods(dragonfly, [spamEmail, wateringHole, customMalware]).
pastTargets(dragonfly, [defense, aerospace, energy]).
pastMotives(dragonfly, [cyberespionage, spy, sabotage]).
%% ?

prominentGroup(govRAT).
pastAttackMethods(govRAT, [clientSideExploits]).
pastTargets(govRAT, [govOfficials, militaryOfficials, enterprises]).
pastMotives(govRAT, [cyberespionage]).

prominentGroup(pawnStorm).
pastAttackMethods(pawnStorm, [spearphishing, phishingWebsites, ios, exploits, zeroday]).
pastTargets(pawnStorm, [nato, govOfficials, militaryOfficials, russia, ukraine]).
pastMotives(pawnStorm, [cyberespionage]).

prominentGroup(waterbug).
pastAttackMethods(waterbug, [zeroday, email, stolenCertificates, wateringHole]).
pastTargets(waterbug, [govInstitutions, embassies, education, research]).
pastMotives(waterbug, [cyberespionage, spy, intelligenceGathering]).

%% Background
listCountries = [china, israel, iran, usa, uk, northkorea, southkorea].
listIndustries = [infocomm].
listChineseCountries = [china].
listEnglishCountries = [usa, uk].

isCountry(X) :- member(X, listCountries).
industry(X) :- member(X, listIndustries).

firstLanguage(chinese, X) :- member(X, listChineseCountries).
firstLanguage(english, X) :- member(X, listEnglishCountries).
% firstLanguage(french, X) :- member(X, listFrenchCountries).
% firstLanguage(arabic, X) :- member(X, listArabicCountries).

isCulprit(equationGroup, flameattack).
malwareUsedInAttack(flame, flameattack).