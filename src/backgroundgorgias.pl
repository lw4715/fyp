






rule(bg7, prominentGroup(equationGrp), []).
rule(bg8, country(equationGrp,usa), []).
rule(bg9, pastTargets(equationGrp,[iran,russia,pakistan,afghanistan,india,syria,mali]), []).



rule(bg13, prominentGroup(anglerEK), []).
rule(bg14, country(anglerEK,ussr), []).
rule(bg15, pastAttackMethods(anglerEK,[driveByDownloads]), []).
rule(bg16, pastMotives(anglerEK,[undergroundBusiness]), []).


rule(bg19, prominentGroup(blackVine), []).
rule(bg20, country(blackVine,china), []).
rule(bg21, pastAttackMethods(blackVine,[zeroday,wateringHole,customMalware]), []).
rule(bg22, pastTargets(blackVine,[aerospace,energy,healthcare]), []).
rule(bg23, pastMotives(blackVine,[cyberespionage]), []).

rule(bg25, prominentGroup(butterfly), []).
rule(bg26, country(butterfly,china), []).
rule(bg27, pastAttackMethods(butterfly,[zeroday,customMalware]), []).
rule(bg28, pastTargets(butterfly,[twitter,facebook,apple,microsoft,pharmaceutical,technology,law,oil,preciousMetalMining]), []).
rule(bg29, pastMotives(butterfly,[cyberespionage,undergroundBusiness]), []).


rule(bg32, prominentGroup(dragonfly), []).
rule(bg33, country(dragonfly,eastEurope), []).
rule(bg34, pastAttackMethods(dragonfly,[spamEmail,wateringHole,customMalware]), []).
rule(bg35, pastTargets(dragonfly,[defense,aerospace,energy]), []).
rule(bg36, pastMotives(dragonfly,[cyberespionage,spy,sabotage]), []).


rule(bg39, prominentGroup(govRAT), []).
rule(bg40, pastAttackMethods(govRAT,[clientSideExploits]), []).
rule(bg41, pastTargets(govRAT,[govOfficials,militaryOfficials,enterprises]), []).
rule(bg42, pastMotives(govRAT,[cyberespionage]), []).

rule(bg44, prominentGroup(pawnStorm), []).
rule(bg45, pastAttackMethods(pawnStorm,[spearphishing,phishingWebsites,ios,exploits,zeroday]), []).
rule(bg46, pastTargets(pawnStorm,[nato,govOfficials,militaryOfficials,russia,ukraine]), []).
rule(bg47, pastMotives(pawnStorm,[cyberespionage]), []).

rule(bg49, prominentGroup(waterbug), []).
rule(bg50, pastAttackMethods(waterbug,[zeroday,email,stolenCertificates,wateringHole]), []).
rule(bg51, pastTargets(waterbug,[govInstitutions,embassies,education,research]), []).
rule(bg52, pastMotives(waterbug,[cyberespionage,spy,intelligenceGathering]), []).


rule(bg55, listCountries=[china,israel,iran,usa,uk,northkorea,southkorea], []).
rule(bg56, listIndustries=[infocomm], []).
rule(bg57, listChineseCountries=[china], []).
rule(bg58, listEnglishCountries=[usa,uk], []).

rule(bg60, isCountry(X), [member(X,listCountries)]).
rule(bg61, industry(X), [member(X,listIndustries)]).

rule(bg63, firstLanguage(chinese,X), [member(X,listChineseCountries)]).
rule(bg64, firstLanguage(english,X), [member(X,listEnglishCountries)]).



rule(bg68, isCulprit(equationGroup,flameattack), []).
rule(bg69, malwareUsedInAttack(flame,flameattack), []).
